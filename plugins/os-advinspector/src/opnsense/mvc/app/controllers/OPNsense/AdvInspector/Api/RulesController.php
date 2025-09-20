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
use OPNsense\Core\Backend;

/**
 * Class RulesController
 *
 * Provides comprehensive API endpoints for managing security rules in the Advanced Network Inspector.
 * Handles complete CRUD operations, bulk management, rule validation, and automatic configuration
 * export to working files used by the inspection engine.
 *
 * Features:
 * - Full CRUD operations for individual security rules
 * - Bulk operations for efficient multi-rule management
 * - Real-time rule validation with detailed error reporting
 * - Automatic configuration synchronization with inspection engine
 * - Rule search and filtering capabilities
 * - Rule enable/disable toggle functionality
 *
 * Rule Structure:
 * - UUID: Unique identifier for each rule
 * - enabled: Rule activation status (0/1)
 * - description: Human-readable rule description
 * - source: Source IP/network specification
 * - destination: Destination IP/network specification
 * - port: Port or port range specification
 * - protocol: Network protocol (tcp, udp, icmp, etc.)
 * - action: Action to take (allow, block, alert, drop)
 * - log: Logging preference for rule matches
 *
 * @package OPNsense\AdvInspector\Api
 * @author Pierpaolo Casati
 */
class RulesController extends ApiMutableModelControllerBase
{
    /**
     * Internal OPNsense model name for rule management
     */
    protected static $internalModelName = 'settings';
    
    /**
     * Internal OPNsense model class for Advanced Inspector settings
     */
    protected static $internalModelClass = '\OPNsense\AdvInspector\Settings';

    /**
     * Search and retrieve security rules with filtering and pagination
     *
     * Provides a searchable interface for retrieving security rules based on
     * various criteria. Supports OPNsense standard search functionality including
     * sorting, filtering, and pagination for efficient rule management in large
     * rule sets.
     *
     * The search operates on key rule fields to help administrators quickly
     * locate specific rules or groups of rules based on their characteristics.
     *
     * @api GET /api/advinspector/rules/searchRule
     * 
     * Query Parameters:
     * @param string $searchPhrase Optional search text to filter rules
     * @param int $current Current page number (default: 0)
     * @param int $rowCount Number of rows per page (default: 10)
     * @param string $sort Column to sort by
     * @param string $sortOrder Sort direction ('asc' or 'desc')
     * 
     * @return array{
     *   current: int,
     *   rowCount: int,
     *   total: int,
     *   rows: array<array<string, mixed>>
     * } Paginated search results with rule data
     * 
     * Response Fields:
     * - current: Current page number
     * - rowCount: Number of rows per page
     * - total: Total number of matching rules
     * - rows: Array of rule objects with searchable fields
     * 
     * Searchable Fields:
     * - enabled: Rule activation status
     * - description: Rule description text
     * - source: Source IP/network specification
     * - destination: Destination IP/network specification
     * - port: Port specification
     * - protocol: Network protocol
     * - action: Rule action (allow/block/alert/drop)
     * - log: Logging preference
     * 
     * @example
     * // Search for rules containing "malware" in any field
     * GET /api/advinspector/rules/searchRule?searchPhrase=malware
     * 
     * // Get second page of results, 25 per page, sorted by description
     * GET /api/advinspector/rules/searchRule?current=1&rowCount=25&sort=description&sortOrder=asc
     */
    public function searchRuleAction()
    {
        return $this->searchBase('rules.rule', [
            'enabled', 'description', 'source', 'destination', 'port', 'protocol', 'action', 'log'
        ]);
    }

    /**
     * Retrieve a specific security rule by UUID
     *
     * Fetches complete details for a single security rule identified by its UUID.
     * Used for rule editing forms, detailed rule inspection, and API integrations
     * that need full rule specifications.
     *
     * @api GET /api/advinspector/rules/getRule/{uuid}
     * 
     * @param string|null $uuid Unique identifier of the rule to retrieve
     * 
     * @return array{
     *   rule: array<string, mixed>|null
     * } Rule data or empty response if not found
     * 
     * Success Response:
     * - rule: Complete rule object with all fields
     * 
     * Error Response:
     * - rule: null (when UUID not found)
     * 
     * Rule Object Fields:
     * - uuid: Unique rule identifier
     * - enabled: Activation status ("0" or "1")
     * - description: Human-readable description
     * - source: Source IP/network (CIDR notation supported)
     * - destination: Destination IP/network (CIDR notation supported)
     * - port: Port specification (single, range, or comma-separated list)
     * - protocol: Network protocol (tcp, udp, icmp, any)
     * - action: Rule action (allow, block, alert, drop)
     * - log: Logging preference ("0" or "1")
     * 
     * @example
     * // Get rule with specific UUID
     * GET /api/advinspector/rules/getRule/12345678-1234-1234-1234-123456789012
     */
    public function getRuleAction($uuid = null)
    {
        return $this->getBase('rule', 'rules.rule', $uuid);
    }

    /**
     * Add a new security rule to the configuration
     *
     * Creates a new security rule with the provided specifications. The rule
     * is automatically assigned a UUID and added to the rule collection.
     * After creation, the configuration is validated and exported to working
     * files for immediate use by the inspection engine.
     *
     * @api POST /api/advinspector/rules/addRule
     * 
     * @param array $request_body Expected POST structure:
     * {
     *   "advinspector": {
     *     "rules": {
     *       "rule": {
     *         "enabled": "1",
     *         "description": "Block malicious IPs",
     *         "source": "192.168.1.0/24",
     *         "destination": "any",
     *         "port": "80,443",
     *         "protocol": "tcp",
     *         "action": "block",
     *         "log": "1"
     *       }
     *     }
     *   }
     * }
     * 
     * @return array{
     *   result: string,
     *   message?: string,
     *   validations?: array<string, string>
     * } Operation result with validation details
     * 
     * Success Response:
     * - result: "saved"
     * - message: Success message (optional)
     * 
     * Validation Error Response:
     * - result: "failed"
     * - validations: Array of field-specific validation errors
     * 
     * Field Validation Rules:
     * - enabled: Must be "0" or "1"
     * - source/destination: Valid IP, network CIDR, or "any"
     * - port: Valid port number, range (1-8080), or comma-separated list
     * - protocol: One of tcp, udp, icmp, any
     * - action: One of allow, block, alert, drop
     * - description: Non-empty string (recommended)
     * 
     * @throws \Exception When model operations fail
     * 
     * @example
     * POST /api/advinspector/rules/addRule
     * Content-Type: application/json
     * {
     *   "advinspector": {
     *     "rules": {
     *       "rule": {
     *         "enabled": "1",
     *         "description": "Block SSH brute force attempts",
     *         "source": "any",
     *         "destination": "192.168.1.0/24", 
     *         "port": "22",
     *         "protocol": "tcp",
     *         "action": "block",
     *         "log": "1"
     *       }
     *     }
     *   }
     * }
     */
    public function addRuleAction()
    {
        // Get the model instance for rule management
        $mdl = $this->getModel();
        
        // Extract rule data from POST request
        $payloadRoot = $this->request->getPost("advinspector") ?? [];
        $payload = $payloadRoot["rules"]["rule"] ?? [];

        // Create new rule node in the model
        $node = $mdl->rules->rule->Add();
        
        // Populate rule fields from payload data
        foreach ($payload as $key => $value) {
            // Only set fields that exist in the model
            if ($node->$key !== null) {
                $node->$key = $value;
            }
        }

        // Validate, save, and export the configuration
        return $this->finalizeAndSave($mdl);
    }

    /**
     * Update an existing security rule
     *
     * Modifies an existing security rule identified by UUID with new values.
     * Only provided fields are updated; omitted fields retain their current values.
     * The updated rule is validated and the configuration is automatically
     * exported for immediate effect.
     *
     * @api POST /api/advinspector/rules/setRule/{uuid}
     * 
     * @param string $uuid Unique identifier of the rule to update
     * 
     * @param array $request_body Expected POST structure (same as addRule):
     * {
     *   "advinspector": {
     *     "rules": {
     *       "rule": {
     *         "description": "Updated rule description",
     *         "action": "alert"
     *       }
     *     }
     *   }
     * }
     * 
     * @return array{
     *   result: string,
     *   message?: string,
     *   validations?: array<string, string>
     * } Operation result
     * 
     * Success Response:
     * - result: "saved"
     * 
     * Error Responses:
     * - result: "error", message: "Rule not found." (UUID not found)
     * - result: "failed", validations: {...} (Validation errors)
     * - result: "error", message: "Exception: ..." (System error)
     * 
     * Update Behavior:
     * - Partial updates supported (only provide fields to change)
     * - UUID cannot be modified
     * - All field validation rules apply
     * - Configuration export triggered automatically
     * 
     * @throws \Exception When model operations fail
     * 
     * @example
     * // Update rule action and description only
     * POST /api/advinspector/rules/setRule/12345678-1234-1234-1234-123456789012
     * {
     *   "advinspector": {
     *     "rules": {
     *       "rule": {
     *         "description": "Updated: Block suspicious traffic",
     *         "action": "alert"
     *       }
     *     }
     *   }
     * }
     */
    public function setRuleAction($uuid)
    {
        try {
            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;
            $node = null;
            
            // Find the rule with matching UUID
            foreach ($collection->iterateItems() as $index => $item) {
                if ((string)$item->getAttributes()["uuid"] === $uuid) {
                    $node = $item;
                    break;
                }
            }

            // Return error if rule not found
            if ($node === null) {
                return ["result" => "error", "message" => "Rule not found."];
            }
            
            // Extract update data from POST request
            $payloadRoot = $this->request->getPost("advinspector") ?? [];
            $payload = $payloadRoot["rules"]["rule"] ?? [];

            // Update only the provided fields
            foreach ($payload as $key => $value) {
                if ($node->$key !== null) {
                    $node->$key = $value;
                }
            }

            // Validate, save, and export the updated configuration
            return $this->finalizeAndSave($mdl);
            
        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Delete a specific security rule
     *
     * Permanently removes a security rule from the configuration. This operation
     * cannot be undone. The rule is identified by its UUID and removed from
     * the rule collection. Configuration is automatically exported after deletion.
     *
     * @api POST /api/advinspector/rules/delRule/{uuid}
     * 
     * @param string $uuid Unique identifier of the rule to delete
     * 
     * @return array{
     *   result: string,
     *   message?: string
     * } Deletion result
     * 
     * Success Response:
     * - result: "deleted"
     * 
     * Error Responses:
     * - result: "error", message: "Rule not found." (UUID not found)
     * - result: "error", message: "Exception: ..." (System error)
     * 
     * Security Considerations:
     * - Deletion is permanent and cannot be undone
     * - Deleted rules are immediately removed from active configuration
     * - No confirmation prompt - implement in UI if needed
     * - Consider disabling rules instead of deleting for audit trail
     * 
     * @throws \Exception When model operations fail
     * 
     * @example
     * // Delete rule with specific UUID
     * POST /api/advinspector/rules/delRule/12345678-1234-1234-1234-123456789012
     */
    public function delRuleAction($uuid)
    {
        try {
            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;
            
            // Find and delete the rule with matching UUID
            foreach ($collection->iterateItems() as $index => $node) {
                if ((string)$node->getAttributes()["uuid"] === $uuid) {
                    $collection->del($index);
                    return $this->finalizeAndSave($mdl, ["result" => "deleted"]);
                }
            }

            // Return error if rule not found
            return ["result" => "error", "message" => "Rule not found."];
            
        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Toggle the enabled/disabled state of a security rule
     *
     * Quickly enables or disables a rule by toggling its "enabled" field.
     * This is a convenience method for rule management interfaces that need
     * to quickly activate or deactivate rules without full editing.
     *
     * @api POST /api/advinspector/rules/toggleRule/{uuid}
     * 
     * @param string $uuid Unique identifier of the rule to toggle
     * 
     * @return array{
     *   result: string,
     *   message?: string
     * } Toggle operation result
     * 
     * Success Response:
     * - result: "toggled"
     * 
     * Error Responses:
     * - result: "error", message: "Rule not found." (UUID not found)
     * - result: "error", message: "Exception: ..." (System error)
     * 
     * Toggle Behavior:
     * - "1" (enabled) becomes "0" (disabled)
     * - "0" (disabled) becomes "1" (enabled)
     * - Configuration exported immediately after toggle
     * - Rule takes effect or is deactivated immediately
     * 
     * Use Cases:
     * - Quick rule activation/deactivation in management interfaces
     * - Temporary rule disabling for testing
     * - Emergency rule activation/deactivation
     * - Bulk rule management workflows
     * 
     * @throws \Exception When model operations fail
     * 
     * @example
     * // Toggle rule state (enabled ↔ disabled)
     * POST /api/advinspector/rules/toggleRule/12345678-1234-1234-1234-123456789012
     */
    public function toggleRuleAction($uuid)
    {
        try {
            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;

            // Find the rule and toggle its enabled state
            foreach ($collection->iterateItems() as $index => $node) {
                if ((string)$node->getAttributes()["uuid"] === $uuid) {
                    // Toggle the "enabled" field between "1" and "0"
                    $node->enabled = ($node->enabled == "1") ? "0" : "1";
                    return $this->finalizeAndSave($mdl, ["result" => "toggled"]);
                }
            }

            // Return error if rule not found
            return ["result" => "error", "message" => "Rule not found."];
            
        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Delete multiple security rules in a single operation
     *
     * Efficiently removes multiple rules specified by their UUIDs in a single
     * transaction. This bulk operation reduces the overhead of individual
     * deletions and ensures atomic operation - either all specified rules
     * are deleted or none are (in case of errors).
     *
     * @api POST /api/advinspector/rules/delRuleBulk
     * 
     * @param array $request_body Expected POST structure:
     * {
     *   "uuids": [
     *     "12345678-1234-1234-1234-123456789012",
     *     "87654321-4321-4321-4321-210987654321",
     *     "abcdefgh-abcd-abcd-abcd-abcdefghijkl"
     *   ]
     * }
     * 
     * @return array{
     *   result: string,
     *   message?: string
     * } Bulk deletion result
     * 
     * Success Response:
     * - result: "deleted" (when at least one rule was found and deleted)
     * 
     * Error Responses:
     * - result: "error", message: "Invalid input" (uuids not an array)
     * - result: "error", message: "No matching rules found" (no UUIDs found)
     * - result: "error", message: "Exception: ..." (System error)
     * 
     * Operation Characteristics:
     * - Atomic operation: all-or-nothing approach
     * - Efficient: single validation and export cycle
     * - Safe: validates all UUIDs before deletion
     * - Order-independent: deletion order doesn't affect results
     * - Graceful: continues even if some UUIDs don't exist
     * 
     * Performance Considerations:
     * - More efficient than individual deletions for large sets
     * - Single configuration export reduces I/O overhead
     * - Memory efficient: processes rules in order
     * 
     * @throws \Exception When model operations fail
     * 
     * @example
     * // Delete multiple rules at once
     * POST /api/advinspector/rules/delRuleBulk
     * Content-Type: application/json
     * {
     *   "uuids": [
     *     "12345678-1234-1234-1234-123456789012",
     *     "87654321-4321-4321-4321-210987654321"
     *   ]
     * }
     */
    public function delRuleBulkAction()
    {
        try {
            // Validate input data
            $uuids = $this->request->getPost("uuids");
            if (!is_array($uuids)) {
                return ["result" => "error", "message" => "Invalid input"];
            }

            $mdl = $this->getModel();
            $collection = $mdl->rules->rule;
            $found = false;

            // First pass: identify indices of rules to delete
            $indicesToDelete = [];
            foreach ($collection->iterateItems() as $index => $node) {
                $nodeUuid = (string)$node->getAttributes()["uuid"];
                if (in_array($nodeUuid, $uuids)) {
                    $indicesToDelete[] = $index;
                    $found = true;
                }
            }

            // Second pass: delete rules from highest index to lowest
            // This prevents index shifting issues during deletion
            rsort($indicesToDelete);
            foreach ($indicesToDelete as $index) {
                $collection->del($index);
            }

            // Finalize the operation
            if ($found) {
                return $this->finalizeAndSave($mdl, ["result" => "deleted"]);
            } else {
                return ["result" => "error", "message" => "No matching rules found"];
            }

        } catch (\Exception $e) {
            return ["result" => "error", "message" => "Exception: " . $e->getMessage()];
        }
    }

    /**
     * Trigger configuration reconfiguration and rule export
     *
     * Forces a reconfiguration of the Advanced Network Inspector by exporting
     * the current rule configuration to working files. This operation ensures
     * that any manual configuration changes or system updates are properly
     * synchronized with the active inspection engine.
     *
     * @api POST /api/advinspector/rules/reconfigure
     * 
     * @return array{
     *   status: string
     * } Reconfiguration result
     * 
     * Response:
     * - status: Output from the configuration export command
     * 
     * Use Cases:
     * - Manual configuration synchronization
     * - Recovery from configuration inconsistencies  
     * - Development and testing workflows
     * - System maintenance operations
     * - Troubleshooting rule application issues
     * 
     * Technical Details:
     * - Executes "advinspector export_rules" backend command
     * - Converts XML configuration to JSON working files
     * - Updates rule engine with current configuration
     * - Does not modify existing rules, only exports them
     * 
     * @example
     * // Force configuration export and synchronization
     * POST /api/advinspector/rules/reconfigure
     */
    public function reconfigureAction()
    {
        // Execute the rule export backend command
        $response = (new Backend())->configdRun("advinspector export_rules");
        return ["status" => $response];
    }

    /**
     * Finalize rule changes with validation, saving, and configuration export
     *
     * This private method handles the common workflow of validating rule changes,
     * saving the configuration to the system, and exporting the working files
     * for the inspection engine. It ensures data consistency and immediate
     * effect of rule changes.
     *
     * @param object $mdl The model instance containing rule changes
     * @param array $result Base result array to return (default: ["result" => "saved"])
     * 
     * @return array{
     *   result: string,
     *   validations?: array<string, string>
     * } Final operation result
     * 
     * Validation Process:
     * 1. Performs comprehensive rule validation
     * 2. Checks field formats and value constraints  
     * 3. Validates network specifications (IP, CIDR, ports)
     * 4. Ensures protocol and action values are valid
     * 
     * Success Path:
     * 1. Serialize model changes to XML configuration
     * 2. Save configuration to persistent storage
     * 3. Export rules to JSON working files
     * 4. Return success result
     * 
     * Error Path:
     * 1. Collect all validation errors
     * 2. Format errors for UI consumption
     * 3. Return failure result with detailed error messages
     * 4. Do not save or export invalid configuration
     * 
     * Validation Error Format:
     * - Field-specific errors with full dot notation paths
     * - Human-readable error messages
     * - Multiple errors per field supported
     * 
     * @throws \Exception When system operations fail
     */
    private function finalizeAndSave($mdl, $result = ["result" => "saved"])
    {
        // Perform comprehensive validation on the rules section
        $valMsgs = $mdl->performValidation(true, 'rules');

        if ($valMsgs->count() > 0) {
            // Collect validation errors for user feedback
            $result = ["result" => "failed", "validations" => []];
            
            foreach ($valMsgs as $msg) {
                $field = $msg->getField();
                // Use full dot notation for field identification in UI
                $result["validations"]["advinspector." . $field] = $msg->getMessage();
            }
            return $result;
        }
        
        // Validation passed - save configuration and export rules
        $mdl->serializeToConfig();
        Config::getInstance()->save();
        
        // Export current configuration to working files for inspection engine
        (new Backend())->configdRun("advinspector export_rules");

        return $result;
    }
}