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
 *    documentation and/or documentation materials provided with the distribution.
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

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 *
 * Provides comprehensive service lifecycle management for the Advanced Network Inspector.
 * This controller handles all service operations including start, stop, restart, status
 * monitoring, and configuration management through the OPNsense backend system.
 *
 * The controller follows the standard OPNsense service management pattern, integrating
 * with the configd backend daemon for secure service operations. It also provides
 * specialized functionality for rule management including import/export operations
 * and configuration synchronization.
 *
 * Service Operations:
 * - Service lifecycle management (start, stop, restart)
 * - Real-time status monitoring
 * - Configuration reconfiguration and rule export
 * - Bulk rule import/export functionality
 * - Integration with OPNsense service framework
 *
 * @package OPNsense\AdvInspector\Api
 * @author Pierpaolo Casati
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    /**
     * Internal model class reference for service configuration
     * 
     * @var string Full namespace path to the Settings model class
     */
    protected static $internalServiceClass = '\OPNsense\AdvInspector\Settings';
    
    /**
     * Template name for service configuration generation
     * 
     * @var string Template path used by configd for service configuration
     */
    protected static $internalServiceTemplate = 'OPNsense/AdvInspector';
    
    /**
     * Configuration path that determines if service is enabled
     * 
     * @var string XPath to the enabled setting in configuration tree
     */
    protected static $internalServiceEnabled = 'general.enabled';
    
    /**
     * Internal service name used by the system
     * 
     * @var string Service name as recognized by configd and system services
     */
    protected static $internalServiceName = 'advinspector';

    /**
     * Start the Advanced Network Inspector service
     * 
     * Initiates the packet inspection service through the OPNsense backend system.
     * The service will begin monitoring configured network interfaces and applying
     * security rules according to the current configuration.
     * 
     * Prerequisites:
     * - Service must be enabled in configuration (general.enabled = 1)
     * - At least one network interface must be configured for monitoring
     * - Valid security rules must be present (or default allow-all applies)
     * 
     * @api POST /api/advinspector/service/start
     * 
     * @return array{response: string} Service start response from backend
     * 
     * Response Format:
     * - response: Backend command output, typically "OK" on success or error message
     * 
     * @throws \Exception When backend communication fails
     * 
     * @example
     * POST /api/advinspector/service/start
     * Response: {"response": "OK"}
     */
    public function startAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector start");
        return array("response" => $response);
    }

    /**
     * Stop the Advanced Network Inspector service
     * 
     * Gracefully shuts down the packet inspection service, stopping all monitoring
     * activities and releasing system resources. Active network connections are
     * allowed to complete, but no new packet analysis will be performed.
     * 
     * The service shutdown process includes:
     * - Stopping packet capture on all monitored interfaces
     * - Completing processing of queued packets
     * - Releasing file handles and network resources
     * - Updating service status to stopped
     * 
     * @api POST /api/advinspector/service/stop
     * 
     * @return array{response: string} Service stop response from backend
     * 
     * Response Format:
     * - response: Backend command output, typically "OK" on success
     * 
     * @throws \Exception When backend communication fails or service is unresponsive
     * 
     * @example
     * POST /api/advinspector/service/stop
     * Response: {"response": "OK"}
     */
    public function stopAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector stop");
        return array("response" => $response);
    }

    /**
     * Restart the Advanced Network Inspector service
     * 
     * Performs a controlled restart of the service, which involves stopping the
     * current instance and starting a fresh one. This operation is useful when
     * configuration changes require a full service restart or when recovering
     * from service issues.
     * 
     * The restart process:
     * 1. Gracefully stops the current service instance
     * 2. Reloads configuration from the current settings
     * 3. Starts a new service instance with updated configuration
     * 4. Resumes packet monitoring and rule enforcement
     * 
     * Note: There may be a brief interruption in packet monitoring during restart.
     * 
     * @api POST /api/advinspector/service/restart
     * 
     * @return array{response: string} Service restart response from backend
     * 
     * Response Format:
     * - response: Backend command output indicating restart status
     * 
     * @throws \Exception When backend communication fails or restart operation fails
     * 
     * @example
     * POST /api/advinspector/service/restart
     * Response: {"response": "restarting"}
     */
    public function restartAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector restart");
        return array("response" => $response);
    }

    /**
     * Reconfigure the Advanced Network Inspector service
     * 
     * Applies updated configuration settings to the running service without
     * requiring a full restart. This operation reloads configuration files,
     * updates security rules, and adjusts service parameters while maintaining
     * continuous packet monitoring.
     * 
     * Reconfiguration includes:
     * - Reloading security rules from configuration
     * - Updating network interface monitoring list
     * - Applying new inspection mode settings
     * - Refreshing logging and alerting parameters
     * 
     * This is the preferred method for applying configuration changes as it
     * minimizes service disruption compared to a full restart.
     * 
     * @api POST /api/advinspector/service/reconfigure
     * 
     * @return array{response: string} Service reconfiguration response from backend
     * 
     * Response Format:
     * - response: Backend command output, typically "OK" when successful
     * 
     * @throws \Exception When backend communication fails or reconfiguration fails
     * 
     * @example
     * POST /api/advinspector/service/reconfigure
     * Response: {"response": "OK"}
     */
    public function reconfigureAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector reconfigure");
        return array("response" => $response);
    }

    /**
     * Get current service status and operational information
     * 
     * Retrieves comprehensive status information about the Advanced Network Inspector
     * service, including operational state, resource usage, and basic statistics.
     * This information is essential for monitoring service health and troubleshooting.
     * 
     * Status information typically includes:
     * - Service running state (running, stopped, error)
     * - Process ID and resource usage
     * - Active interface monitoring status
     * - Basic packet processing statistics
     * - Configuration validation status
     * 
     * @api GET /api/advinspector/service/status
     * 
     * @return array{response: string} Service status information from backend
     * 
     * Response Format:
     * - response: Formatted status output containing service state and metrics
     * 
     * Status Response Examples:
     * - "running" - Service is active and monitoring traffic
     * - "stopped" - Service is not running
     * - "error" - Service encountered an error and is not operational
     * 
     * @throws \Exception When backend communication fails
     * 
     * @example
     * GET /api/advinspector/service/status
     * Response: {"response": "running (pid: 12345, interfaces: 2, rules: 45)"}
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector status");
        return array("response" => $response);
    }

    /**
     * Export security rules to JSON format
     * 
     * Triggers the export of current security rules from the OPNsense configuration
     * to the JSON format used by the inspection engine. This operation is typically
     * performed automatically when rules are modified, but can be manually triggered
     * for troubleshooting or validation purposes.
     * 
     * The export process:
     * 1. Reads current rule configuration from XML config
     * 2. Validates rule syntax and structure
     * 3. Converts rules to JSON format with proper field mapping
     * 4. Writes JSON rules file for consumption by inspection engine
     * 
     * @api POST /api/advinspector/service/export_rules
     * 
     * @return array{response: string} Rule export operation response
     * 
     * Response Format:
     * - response: Export status message, typically rule count or error information
     * 
     * @throws \Exception When rule export fails or configuration is invalid
     * 
     * @example
     * POST /api/advinspector/service/export_rules
     * Response: {"response": "Exported 127 rules successfully"}
     */
    public function export_rulesAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("advinspector export_rules");
        return ["response" => $response];
    }

    /**
     * Import security rules from JSON format with bulk replacement
     * 
     * Imports a complete set of security rules from a JSON payload, replacing
     * all existing rules in the system. This function is designed for bulk
     * rule management, backup restoration, and rule set deployment scenarios.
     * 
     * IMPORTANT: This operation completely replaces the existing rule set.
     * All current rules will be permanently deleted and replaced with the
     * imported rules. Use with caution in production environments.
     * 
     * Input Format:
     * The request must contain base64-encoded JSON data with the following structure:
     * {
     *   "rules": [
     *     {
     *       "uuid": "rule-uuid-here",
     *       "enabled": "1",
     *       "description": "Rule description",
     *       "source": "192.168.1.0/24",
     *       "destination": "any",
     *       "port": "80,443",
     *       "protocol": "tcp",
     *       "action": "allow"
     *     }
     *   ]
     * }
     * 
     * @api POST /api/advinspector/service/import_rules
     * 
     * Request Body:
     * @param string $content Base64-encoded JSON rule data
     * 
     * @return array{status: string, message?: string} Import operation result
     * 
     * Success Response:
     * - status: "ok" when import completes successfully
     * 
     * Error Responses:
     * - status: "error", message: "Invalid JSON format" - JSON parsing failed
     * - status: "failed", message: "Missing POST content" - No data provided
     * 
     * Security Considerations:
     * - Input validation ensures only valid rule fields are processed
     * - JSON structure validation prevents malformed data injection  
     * - Configuration backup is recommended before import operations
     * - Rule validation occurs during configuration serialization
     * 
     * @throws \Exception When model operations fail or configuration cannot be saved
     * 
     * @example
     * POST /api/advinspector/service/import_rules
     * Content-Type: application/x-www-form-urlencoded
     * Body: content=eyJydWxlcyI6W3sidXVpZCI6InRlc3QiLCJlbmFibGVkIjoiMSJ9XX0=
     * Response: {"status": "ok"}
     */
    public function import_rulesAction()
    {
        // Initialize result with failure status
        $result = ["status" => "failed"];
        
        // Validate request method
        if (!$this->request->isPost()) {
            return ["status" => "error", "message" => "Only POST method allowed"];
        }

        try {
            // Extract base64-encoded content from POST data
            $base64 = $this->request->getPost("content");
            if (empty($base64)) {
                return ["status" => "failed", "message" => "Missing POST content"];
            }

            // Decode base64 content to JSON string
            $json = base64_decode($base64);
            if ($json === false) {
                return ["status" => "error", "message" => "Invalid base64 encoding"];
            }

            // Parse JSON data with error handling
            $parsed = json_decode($json, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return [
                    "status" => "error", 
                    "message" => "Invalid JSON format: " . json_last_error_msg()
                ];
            }

            // Validate JSON structure contains rules array
            if (!isset($parsed["rules"]) || !is_array($parsed["rules"])) {
                return [
                    "status" => "error", 
                    "message" => "Missing or invalid 'rules' array in JSON data"
                ];
            }

            // Initialize Rules model for rule management
            $mdl = new \OPNsense\AdvInspector\Rules();
            
            // Clear all existing rules (DESTRUCTIVE OPERATION)
            $mdl->rules->rule->clear();
            
            $importedCount = 0;
            
            // Import each rule from the JSON data
            foreach ($parsed["rules"] as $ruleData) {
                if (!is_array($ruleData)) {
                    continue; // Skip non-array entries
                }
                
                // Create new rule node in configuration
                $node = $mdl->rules->rule->Add();
                
                // Set rule fields, validating against model structure
                foreach ($ruleData as $key => $value) {
                    if ($node->hasField($key)) {
                        $node->$key = $value;
                    }
                    // Silently ignore unknown fields for forward compatibility
                }
                
                $importedCount++;
            }

            // Serialize configuration and save to XML
            $mdl->serializeToConfig();
            \OPNsense\Core\Config::getInstance()->save();
            
            // Export rules to JSON format for inspection engine
            $backend = new Backend();
            $exportResult = $backend->configdRun("advinspector export_rules");
            
            return [
                "status" => "ok",
                "message" => "Successfully imported {$importedCount} rules",
                "export_result" => $exportResult
            ];
            
        } catch (\Exception $e) {
            return [
                "status" => "error",
                "message" => "Import failed: " . $e->getMessage()
            ];
        }
    }
}