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

/**
 * Class RulesController
 *
 * Web interface controller for Advanced Network Inspector security rules management.
 * This controller provides the main interface for creating, editing, and managing
 * security rules that govern network packet inspection and threat detection behavior.
 *
 * The RulesController serves as the presentation layer for the comprehensive rule
 * management system, rendering interfaces that allow security administrators to
 * define, modify, and organize security policies through an intuitive web-based
 * management console.
 *
 * Rule Management Features:
 * - Interactive rule creation and editing through modal dialogs
 * - Bulk rule operations (enable/disable, delete, import/export)
 * - Rule validation with real-time feedback and error reporting
 * - Rule testing and simulation capabilities
 * - Rule organization with priorities and categorization
 * - Template-based rule creation for common security patterns
 *
 * Interface Components:
 * - DataGrid-based rule listing with sorting and filtering
 * - Modal dialog forms for rule creation and editing
 * - Drag-and-drop rule reordering for priority management
 * - Bulk action controls for efficient rule management
 * - Import/export functionality for rule backup and sharing
 * - Real-time rule validation and syntax checking
 *
 * Security Policy Integration:
 * - Integration with threat intelligence feeds
 * - Predefined rule templates for common attack patterns
 * - Custom rule creation with advanced condition builders
 * - Rule effectiveness analytics and optimization suggestions
 * - Compliance template support for regulatory requirements
 *
 * @package OPNsense\AdvInspector
 * @author Pierpaolo Casati
 */
class RulesController extends \OPNsense\Base\IndexController
{
    /**
     * Render the main security rules management interface
     *
     * This action initializes and renders the comprehensive rules management interface,
     * including the main rule listing table and the associated modal dialog forms
     * for rule creation and editing. The method prepares all necessary form components
     * and view data required for the interactive rule management experience.
     *
     * The interface provides security administrators with powerful tools for managing
     * the rule set that governs network packet inspection behavior. Rules define
     * how the system should respond to different types of network traffic based on
     * various criteria such as source/destination addresses, ports, protocols, and
     * content patterns.
     *
     * Form Dialog Preparation:
     * The method extracts and processes the rule dialog form definition to prepare
     * it for client-side rendering. This includes:
     * - Loading form field definitions from the model
     * - Filtering field components for proper rendering
     * - Setting up form metadata (ID, labels, descriptions)
     * - Preparing validation rules and constraints
     *
     * Interface Features Enabled:
     * - Dynamic rule table with real-time updates
     * - Modal dialog forms with validation and error handling
     * - Bulk operations for multiple rule management
     * - Drag-and-drop rule reordering capabilities
     * - Advanced search and filtering options
     * - Export/import functionality for rule sets
     *
     * Client-Side Integration:
     * The rendered interface integrates with various API endpoints:
     * - /api/advinspector/rules/searchRule - Rule listing and filtering
     * - /api/advinspector/rules/addRule - New rule creation
     * - /api/advinspector/rules/setRule - Rule modification
     * - /api/advinspector/rules/delRule - Rule deletion
     * - /api/advinspector/rules/toggleRule - Rule enable/disable
     * - /api/advinspector/rules/delRuleBulk - Bulk rule operations
     *
     * @route GET /ui/advinspector/rules
     *
     * @return void This method renders a view template and populates view variables
     *
     * View Template: 'OPNsense/AdvInspector/rules'
     * - Template Location: /usr/local/opnsense/mvc/app/views/OPNsense/AdvInspector/rules.volt
     * - Contains: Rule management interface with DataGrid and modal dialogs
     * - Includes: JavaScript for dynamic form handling and API integration
     * - Utilizes: OPNsense UI framework components and Bootstrap modals
     *
     * View Variables Set:
     * @var array $formDialogRuleFields Filtered form fields for modal dialog rendering
     * @var string $dialogRuleID Form identifier for the rule dialog
     * @var string $dialogRuleLabel Human-readable label for the dialog
     * @var array $formDialogRule Complete form definition for rule dialog
     *
     * Form Dialog Configuration:
     * The rule dialog form includes fields for:
     * - Rule identification (name, description, UUID)
     * - Network criteria (source/destination IPs, ports, protocols)
     * - Rule actions (allow, block, alert, log)
     * - Rule metadata (priority, category, enabled status)
     * - Advanced options (custom patterns, time restrictions)
     *
     * Security and Validation:
     * - Form fields include client-side and server-side validation
     * - Input sanitization for all user-provided data
     * - Role-based access control for rule modification
     * - Audit logging of all rule changes
     * - Configuration backup before significant changes
     *
     * Performance Considerations:
     * - Efficient form field filtering to reduce client-side payload
     * - Lazy loading of rule data through AJAX pagination
     * - Optimized form rendering for large rule sets
     * - Client-side caching of form definitions
     *
     * @throws \Exception When form definition cannot be loaded or processed
     * @throws \RuntimeException When required model components are unavailable
     * @throws \InvalidArgumentException When form configuration is malformed
     *
     * @example
     * // Administrator accesses rules management
     * GET /ui/advinspector/rules
     * 
     * // Controller processes form definition and renders interface
     * Form: dialogRule -> Extracted fields and metadata
     * Template: OPNsense/AdvInspector/rules.volt
     * 
     * // Page loads with empty rule table and prepared dialog
     * AJAX: GET /api/advinspector/rules/searchRule (loads existing rules)
     * 
     * // User clicks "Add Rule" button
     * Action: Modal dialog opens with form fields
     * Fields: name, description, source, destination, port, protocol, action
     * 
     * // User submits new rule
     * POST /api/advinspector/rules/addRule
     * Response: Rule created and table refreshed
     */
    public function indexAction()
    {
        // Load the rule dialog form definition from the model
        // This form defines all the fields, validation rules, and metadata
        // required for creating and editing security rules
        $form =  $this->getForm("dialogRule");

        // Filter the form array to extract only the field definitions
        // This removes metadata and keeps only the renderable form fields
        // The filtering uses array keys to identify field components vs metadata
        $fieldsOnly = array_filter($form, function($key) {
            return is_int($key); // Field definitions have integer keys
        }, ARRAY_FILTER_USE_KEY);

        // Extract form metadata for dialog configuration
        $this->view->formDialogRuleFields = $fieldsOnly; // Filtered field array
        $this->view->dialogRuleID = $form["id"];  // Form identifier
        $this->view->dialogRuleLabel = $form["description"]; // Dialog title
        
        // Assign the complete form definition to the view for advanced processing
        // This includes all form metadata, validation rules, and configuration
        $this->view->formDialogRule = $form;

        // Select and render the rules management template
        // This template contains the DataGrid for rule listing and the
        // modal dialog structure for rule creation and editing
        $this->view->pick('OPNsense/AdvInspector/rules');
    }
}