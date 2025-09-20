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

namespace OPNsense\AdvInspector\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

/**
 * Class SettingsController
 *
 * Manages configuration settings for the Advanced Network Inspector through
 * the OPNsense model framework. Provides basic CRUD operations for reading
 * and updating system configuration with integrated validation.
 *
 * This controller handles the core configuration management functionality,
 * focusing on the general settings section including service enablement,
 * inspection modes, network interfaces, and operational parameters.
 *
 * Key Features:
 * - Configuration retrieval with full node tree access
 * - Settings validation using OPNsense model framework
 * - Automatic configuration persistence and synchronization
 * - Error handling with detailed validation feedback
 *
 * @package OPNsense\AdvInspector\Api
 * @author Pierpaolo Casati
 */
class SettingsController extends ApiMutableModelControllerBase
{
    /**
     * Internal model name for OPNsense framework integration
     *
     * This property defines the model identifier used by the parent class
     * to locate and instantiate the appropriate configuration model.
     *
     * @var string Model identifier used by OPNsense framework
     */
    protected static $internalModelName = 'settings';

    /**
     * Full class path to the configuration model
     *
     * Specifies the complete namespace and class name of the Settings model
     * that contains the configuration structure and validation rules for
     * the Advanced Network Inspector.
     *
     * @var string Complete class path to Settings model
     */
    protected static $internalModelClass = '\OPNsense\AdvInspector\Settings';

    /**
     * Retrieve current Advanced Network Inspector configuration settings
     *
     * Returns the complete configuration tree for the Advanced Network Inspector,
     * including all sections and subsections. The response contains the raw
     * configuration nodes as stored in the OPNsense configuration system.
     *
     * This method provides read-only access to all configuration parameters
     * including general settings, rule definitions, and any custom configuration
     * sections that may have been added to the system.
     *
     * Configuration Structure Returned:
     * - general: Core service settings (enabled, mode, interfaces, etc.)
     * - rules: Security rule definitions (if present)
     * - Any additional configuration sections defined in the model
     *
     * @api GET /api/advinspector/settings/get
     *
     * @return array{advinspector?: object} Complete configuration tree
     *
     * Response Format:
     * - advinspector: Object containing all configuration nodes and values
     * - Empty array if GET request validation fails
     *
     * Security Considerations:
     * - Only GET requests are processed for security
     * - Full configuration tree is returned (may contain sensitive data)
     * - No authentication/authorization checks beyond OPNsense framework
     *
     * @throws \Exception When model instantiation or node retrieval fails
     *
     * @example
     * GET /api/advinspector/settings/get
     * Response: {
     *   "advinspector": {
     *     "general": {
     *       "enabled": "1",
     *       "inspection_mode": "stateful",
     *       "interfaces": "lan,opt1",
     *       "verbosity": "v"
     *     }
     *   }
     * }
     */
    public function getAction()
    {
        $result = [];

        // Process only GET requests for security and RESTful compliance
        if ($this->request->isGet()) {
            // Get model instance through parent class framework
            $mdlAdvInspector = $this->getModel();

            // Retrieve complete configuration node tree
            $result['advinspector'] = $mdlAdvInspector->getNodes();
        }

        return $result;
    }

    /**
     * Update Advanced Network Inspector configuration settings
     *
     * Accepts configuration updates for the general settings section and applies
     * them to the system configuration after comprehensive validation. The method
     * processes POST data, validates it against the model constraints, and either
     * saves the configuration or returns detailed validation errors.
     *
     * This method specifically focuses on the 'general' configuration section
     * to prevent accidental modification of critical system components or
     * rule definitions that should be managed through dedicated interfaces.
     *
     * Validation Process:
     * 1. Extract configuration data from POST request
     * 2. Apply data to configuration model
     * 3. Validate against model-defined constraints
     * 4. Either save configuration or return validation errors
     * 5. Automatically persist changes to system configuration
     *
     * @api POST /api/advinspector/settings/set
     *
     * Request Body Format:
     * {
     *   "advinspector": {
     *     "general": {
     *       "enabled": "1",
     *       "inspection_mode": "stateful",
     *       "interfaces": "lan,opt1",
     *       "homenet": "192.168.1.0/24",
     *       "verbosity": "v",
     *       "promisc": "0",
     *       "ips": "1"
     *     }
     *   }
     * }
     *
     * @return array{result: string, validations?: array<string, string>} Operation result
     *
     * Success Response:
     * - result: "saved" when configuration is successfully updated
     *
     * Validation Failure Response:
     * - result: "failed" when validation errors are encountered
     * - validations: Object mapping field paths to error messages
     *
     * Error Response:
     * - result: "failed" for any other failure scenario
     *
     * Field Validation:
     * - enabled: Must be "0" or "1"
     * - inspection_mode: Must be one of "stateless", "stateful", "both"
     * - interfaces: Comma-separated list of valid interface names
     * - homenet: Valid CIDR network specifications
     * - verbosity: Must be one of "default", "v", "vv", "vvv", "vvvv", "vvvvv"
     * - promisc: Must be "0" or "1"
     * - ips: Must be "0" or "1"
     *
     * @throws \Exception When model operations or configuration saving fails
     *
     * @example
     * POST /api/advinspector/settings/set
     * Content-Type: application/json
     * Body: {"advinspector": {"general": {"enabled": "1", "inspection_mode": "stateful"}}}
     * Response: {"result": "saved"}
     *
     * @example
     * POST /api/advinspector/settings/set
     * Body: {"advinspector": {"general": {"enabled": "invalid"}}}
     * Response: {
     *   "result": "failed",
     *   "validations": {
     *     "advinspector.general.enabled": "Value must be 0 or 1"
     *   }
     * }
     */
    public function setAction()
    {
        // Initialize result with failure status as default
        $result = ["result" => "failed"];

        // Process only POST requests for data modification security
        if ($this->request->isPost()) {
            // Get model instance for configuration management
            $mdlAdvInspector = $this->getModel();

            // Extract configuration data from POST request
            $configurationData = $this->request->getPost("advinspector");

            // Apply new configuration values to model
            $mdlAdvInspector->setNodes($configurationData);

            // Perform validation specifically on general settings section
            // This prevents modification of other configuration sections
            $validationMessages = $mdlAdvInspector->performValidation(true, 'general');

            if ($validationMessages->count() > 0) {
                // Validation failed - collect and return error messages
                $result["validations"] = [];

                foreach ($validationMessages as $message) {
                    $fieldPath = $message->getField();
                    $errorMessage = $message->getMessage();

                    // Build field path with proper namespace for frontend
                    $result["validations"]["advinspector." . $fieldPath] = $errorMessage;
                }
            } else {
                // Validation successful - persist configuration changes
                $mdlAdvInspector->serializeToConfig();

                // Save configuration to system files
                Config::getInstance()->save();

                // Update result to indicate successful save
                $result["result"] = "saved";
            }
        }

        return $result;
    }
}