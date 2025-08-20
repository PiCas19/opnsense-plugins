// src/routes/firewall.js
const express = require('express');

// Auth opzionale: se manca il modulo, tutto diventa no-op
let authenticate = (req, _res, next) => next();
let authorize = () => (req, _res, next) => next();
let PERMISSIONS = {};
try {
  ({ authenticate, authorize, PERMISSIONS } = require('../middleware/auth'));
} catch (_) {
  // nessuna auth in dev / ambienti senza auth
}

const { validators } = require('../middleware/validation');
const { auditLog, AUDITED_ACTIONS } = require('../middleware/audit');
const { createRateLimiter } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError, ValidationError } = require('../middleware/errorHandler');
const OpnsenseService = require('../services/OpnsenseService');
const logger = require('../utils/logger');

const router = express.Router();

// helpers
const getUserId = (req) => (req.user && req.user.id) ? req.user.id : null;

// rate limiters locali
const firewallLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 300 : 5000,
});
const criticalLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 10 : 100,
});

// Applica limiter e auth
router.use(firewallLimiter);
router.use(authenticate);

/**
 * @swagger
 * components:
 *   schemas:
 *     FirewallRule:
 *       type: object
 *       properties:
 *         uuid:
 *           type: string
 *           description: Unique identifier for the rule
 *           example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *         description:
 *           type: string
 *           description: Human-readable description of the rule
 *           example: "Block malicious IPs from threat intelligence"
 *         interface:
 *           type: string
 *           enum: [wan, lan, opt1, opt2, opt3, dmz]
 *           description: Network interface the rule applies to
 *           example: "wan"
 *         action:
 *           type: string
 *           enum: [pass, block, reject]
 *           description: Action to take when rule matches
 *           example: "block"
 *         enabled:
 *           type: boolean
 *           description: Whether the rule is currently active
 *           example: true
 *         source:
 *           type: string
 *           description: Source IP address or network (CIDR notation or 'any')
 *           example: "192.168.100.0/24"
 *         destination:
 *           type: string
 *           description: Destination IP address or network (CIDR notation or 'any')
 *           example: "any"
 *         protocol:
 *           type: string
 *           enum: [tcp, udp, icmp, any]
 *           description: Network protocol
 *           example: "tcp"
 *         source_port:
 *           type: string
 *           description: Source port or port range
 *           example: "1024-65535"
 *         destination_port:
 *           type: string
 *           description: Destination port or port range
 *           example: "80,443"
 *         source_type:
 *           type: string
 *           enum: [filter, automation, config, demo]
 *           description: Origin of the rule (filter=WebUI, automation=API)
 *           example: "filter"
 *         manageable:
 *           type: boolean
 *           description: Whether the rule can be modified
 *           example: true
 *         created_via:
 *           type: string
 *           description: How the rule was created
 *           example: "WebUI"
 *         created:
 *           type: string
 *           format: date-time
 *           description: When the rule was created
 *           example: "2024-01-15T10:30:00Z"
 *         log:
 *           type: boolean
 *           description: Whether to log packets matching this rule
 *           example: true
 *     
 *     FirewallRuleInput:
 *       type: object
 *       required:
 *         - description
 *         - interface
 *         - action
 *       properties:
 *         description:
 *           type: string
 *           minLength: 1
 *           maxLength: 255
 *           description: Human-readable description of the rule
 *           example: "Block suspicious traffic from external networks"
 *         interface:
 *           type: string
 *           enum: [wan, lan, opt1, opt2, opt3, dmz]
 *           description: Network interface the rule applies to
 *           example: "wan"
 *         action:
 *           type: string
 *           enum: [pass, block, reject]
 *           description: Action to take when rule matches
 *           example: "block"
 *         enabled:
 *           type: boolean
 *           default: true
 *           description: Whether the rule should be active
 *           example: true
 *         source:
 *           type: string
 *           default: "any"
 *           description: Source IP address or network (CIDR notation or 'any')
 *           example: "192.168.100.0/24"
 *         destination:
 *           type: string
 *           default: "any"
 *           description: Destination IP address or network (CIDR notation or 'any')
 *           example: "192.168.1.0/24"
 *         protocol:
 *           type: string
 *           enum: [tcp, udp, icmp, any]
 *           default: "any"
 *           description: Network protocol
 *           example: "tcp"
 *         source_port:
 *           type: string
 *           description: Source port or port range
 *           example: "any"
 *         destination_port:
 *           type: string
 *           description: Destination port or port range
 *           example: "80,443,8080-8090"
 *         log:
 *           type: boolean
 *           default: false
 *           description: Whether to log packets matching this rule
 *           example: true
 *         api_managed:
 *           type: boolean
 *           default: false
 *           description: Whether to create as API-managed rule (separate from WebUI)
 *           example: false
 *     
 *     FirewallStats:
 *       type: object
 *       properties:
 *         total_rules:
 *           type: integer
 *           description: Total number of firewall rules
 *           example: 42
 *         enabled_rules:
 *           type: integer
 *           description: Number of enabled rules
 *           example: 35
 *         disabled_rules:
 *           type: integer
 *           description: Number of disabled rules
 *           example: 7
 *         by_interface:
 *           type: object
 *           description: Rules count grouped by interface
 *           example:
 *             wan: 15
 *             lan: 20
 *             dmz: 7
 *         by_action:
 *           type: object
 *           description: Rules count grouped by action
 *           example:
 *             pass: 25
 *             block: 15
 *             reject: 2
 *         by_source_type:
 *           type: object
 *           description: Rules count grouped by source type
 *           example:
 *             filter: 30
 *             automation: 10
 *             config: 2
 *         system_health:
 *           type: object
 *           properties:
 *             opnsense_connected:
 *               type: boolean
 *               example: true
 *             api_response_time_ms:
 *               type: integer
 *               example: 245
 *             last_config_apply:
 *               type: string
 *               format: date-time
 *               example: "2024-01-15T10:30:00Z"
 *     
 *     PaginationInfo:
 *       type: object
 *       properties:
 *         current_page:
 *           type: integer
 *           minimum: 1
 *           example: 1
 *         per_page:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           example: 20
 *         total:
 *           type: integer
 *           minimum: 0
 *           example: 42
 *         total_pages:
 *           type: integer
 *           minimum: 0
 *           example: 3
 *         has_next:
 *           type: boolean
 *           example: true
 *         has_prev:
 *           type: boolean
 *           example: false
 *     
 *     ApiResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           description: Whether the operation was successful
 *           example: true
 *         message:
 *           type: string
 *           description: Human-readable status message
 *           example: "Operation completed successfully"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           description: When the response was generated
 *           example: "2024-01-15T10:30:00Z"
 *     
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: false
 *         error:
 *           type: string
 *           description: Error message
 *           example: "Validation failed"
 *         details:
 *           type: object
 *           description: Additional error details
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2024-01-15T10:30:00Z"
 */

/**
 * @swagger
 * /api/v1/firewall/rules:
 *   get:
 *     summary: List firewall rules with advanced filtering and pagination
 *     description: Retrieves firewall rules from OPNsense with support for filtering by interface, action, status, and text search. Includes rules from both WebUI and API sources.
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *         description: Number of rules per page
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search term to filter rules by description, source, or destination
 *         example: "malicious"
 *       - in: query
 *         name: interface
 *         schema:
 *           type: string
 *           enum: [wan, lan, opt1, opt2, opt3, dmz]
 *         description: Filter by network interface
 *         example: "wan"
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *           enum: [pass, block, reject]
 *         description: Filter by rule action
 *         example: "block"
 *       - in: query
 *         name: enabled
 *         schema:
 *           type: boolean
 *         description: Filter by rule status (enabled/disabled)
 *         example: true
 *       - in: query
 *         name: protocol
 *         schema:
 *           type: string
 *           enum: [tcp, udp, icmp, any]
 *         description: Filter by protocol
 *         example: "tcp"
 *       - in: query
 *         name: source_type
 *         schema:
 *           type: string
 *           enum: [filter, automation, config, all]
 *         description: Filter by rule source type
 *         example: "filter"
 *     responses:
 *       200:
 *         description: Firewall rules retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/FirewallRule'
 *                     pagination:
 *                       $ref: '#/components/schemas/PaginationInfo'
 *                     summary:
 *                       $ref: '#/components/schemas/FirewallStats'
 *             examples:
 *               success:
 *                 summary: Successful response with rules
 *                 value:
 *                   success: true
 *                   message: "Firewall rules retrieved successfully"
 *                   data:
 *                     - uuid: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                       description: "Block malicious IPs"
 *                       interface: "wan"
 *                       action: "block"
 *                       enabled: true
 *                       source: "192.168.100.0/24"
 *                       destination: "any"
 *                       protocol: "tcp"
 *                       source_type: "filter"
 *                       manageable: true
 *                       created_via: "WebUI"
 *                   pagination:
 *                     current_page: 1
 *                     per_page: 20
 *                     total: 42
 *                     total_pages: 3
 *                     has_next: true
 *                     has_prev: false
 *                   summary:
 *                     total_rules: 42
 *                     enabled_rules: 35
 *                     disabled_rules: 7
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       400:
 *         description: Invalid query parameters
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       429:
 *         description: Rate limit exceeded
 *       500:
 *         description: Internal server error or OPNsense API failure
 */
router.get(
  '/rules',
  validators.firewallRulesQuery,
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      search,
      interface: interfaceFilter,
      action,
      enabled,
      protocol,
      source_type
    } = req.query;

    logger.info('GET /rules called - fetching from OPNsense API', { 
      page, 
      limit, 
      filters: { search, interfaceFilter, action, enabled, protocol, source_type },
      user_id: getUserId(req)
    });

    const filters = {
      interface: interfaceFilter,
      action,
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined,
      protocol,
      search,
      source_type
    };

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get all rules first, then apply pagination in memory
      // This is needed because OPNsense API pagination varies by endpoint
      const allRules = await opnsenseService.getFirewallRules(filters);
      
      // Apply pagination
      const pageNum = parseInt(page, 10);
      const limitNum = parseInt(limit, 10);
      const startIndex = (pageNum - 1) * limitNum;
      const endIndex = startIndex + limitNum;
      const paginatedRules = allRules.slice(startIndex, endIndex);

      const pagination = {
        current_page: pageNum,
        per_page: limitNum,
        total: allRules.length,
        total_pages: Math.ceil(allRules.length / limitNum),
        has_next: pageNum < Math.ceil(allRules.length / limitNum),
        has_prev: pageNum > 1,
      };

      // Enhanced summary with detailed breakdowns
      const summary = {
        total_rules: allRules.length,
        enabled_rules: allRules.filter(r => r.enabled).length,
        disabled_rules: allRules.filter(r => !r.enabled).length,
        by_interface: {},
        by_action: {},
        by_source_type: {},
        by_protocol: {}
      };

      for (const rule of allRules) {
        // Count by interface
        summary.by_interface[rule.interface] = (summary.by_interface[rule.interface] || 0) + 1;
        
        // Count by action
        summary.by_action[rule.action] = (summary.by_action[rule.action] || 0) + 1;
        
        // Count by source type
        summary.by_source_type[rule.source_type] = (summary.by_source_type[rule.source_type] || 0) + 1;
        
        // Count by protocol
        summary.by_protocol[rule.protocol || 'any'] = (summary.by_protocol[rule.protocol || 'any'] || 0) + 1;
      }

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'list_firewall_rules',
        filters,
        total_count: allRules.length,
        returned_count: paginatedRules.length,
        user_id: getUserId(req)
      });

      logger.info(`Rules retrieved successfully from OPNsense: ${allRules.length} total, ${paginatedRules.length} returned`, {
        user_id: getUserId(req),
        filters
      });

      res.json({
        success: true,
        message: 'Firewall rules retrieved successfully',
        data: paginatedRules,
        pagination,
        summary,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error fetching rules from OPNsense API:', { 
        error: error.message, 
        stack: error.stack,
        filters: req.query,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to retrieve firewall rules from OPNsense: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   get:
 *     summary: Get specific firewall rule by ID
 *     description: Retrieves detailed information about a specific firewall rule including its configuration and metadata
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *         example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Firewall rule retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/FirewallRule'
 *             examples:
 *               success:
 *                 summary: Successful response with rule details
 *                 value:
 *                   success: true
 *                   message: "Firewall rule retrieved successfully"
 *                   data:
 *                     uuid: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                     description: "Block malicious IPs from threat intelligence"
 *                     interface: "wan"
 *                     action: "block"
 *                     enabled: true
 *                     source: "192.168.100.0/24"
 *                     destination: "any"
 *                     protocol: "tcp"
 *                     source_type: "filter"
 *                     manageable: true
 *                     created_via: "WebUI"
 *                     created: "2024-01-15T10:30:00Z"
 *                     log: true
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       404:
 *         description: Firewall rule not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             examples:
 *               not_found:
 *                 summary: Rule not found
 *                 value:
 *                   success: false
 *                   error: "Firewall rule not found"
 *                   details:
 *                     rule_id: "invalid-rule-id"
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       500:
 *         description: Internal server error
 */
router.get(
  '/rules/:id',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    logger.info(`GET /rules/${id} called - fetching from OPNsense API`, {
      rule_id: id,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const rule = await opnsenseService.getFirewallRuleById(id);

      if (!rule) {
        throw new NotFoundError(`Firewall rule with ID ${id} not found`);
      }

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'get_firewall_rule',
        rule_id: id,
        rule_description: rule.description,
        user_id: getUserId(req)
      });

      logger.info(`Rule ${id} retrieved successfully from OPNsense`, {
        rule_id: id,
        description: rule.description,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Firewall rule retrieved successfully',
        data: rule,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      
      logger.error(`Error fetching rule ${id} from OPNsense API:`, { 
        error: error.message,
        rule_id: id,
        user_id: getUserId(req)
      });
      
      throw new NotFoundError(`Firewall rule with ID ${id} not found or inaccessible`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}/toggle:
 *   post:
 *     summary: Toggle firewall rule enabled/disabled status
 *     description: Enable or disable a specific firewall rule. This is a common operation for incident response and rule management.
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *         example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - enabled
 *             properties:
 *               enabled:
 *                 type: boolean
 *                 description: Whether to enable (true) or disable (false) the rule
 *                 example: false
 *               reason:
 *                 type: string
 *                 description: Reason for the change (for audit logging)
 *                 example: "SIEM alert: suspicious activity detected"
 *           examples:
 *             disable_rule:
 *               summary: Disable a rule
 *               value:
 *                 enabled: false
 *                 reason: "Security incident response - blocking suspicious IPs"
 *             enable_rule:
 *               summary: Enable a rule
 *               value:
 *                 enabled: true
 *                 reason: "Incident resolved - re-enabling traffic"
 *     responses:
 *       200:
 *         description: Rule toggled successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         rule_id:
 *                           type: string
 *                           example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                         enabled:
 *                           type: boolean
 *                           example: false
 *                         previous_state:
 *                           type: boolean
 *                           example: true
 *                         config_applied:
 *                           type: boolean
 *                           example: true
 *             examples:
 *               success:
 *                 summary: Rule disabled successfully
 *                 value:
 *                   success: true
 *                   message: "Rule disabled successfully"
 *                   data:
 *                     rule_id: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                     enabled: false
 *                     previous_state: true
 *                     config_applied: true
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       400:
 *         description: Invalid request data
 *       404:
 *         description: Rule not found or not manageable
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       429:
 *         description: Rate limit exceeded
 *       500:
 *         description: Internal server error
 */
router.post(
  '/rules/:id/toggle',
  validators.idParam,
  criticalLimiter, // Use stricter rate limiting for rule modifications
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { enabled, reason } = req.body;

    // Validate input
    if (typeof enabled !== 'boolean') {
      throw new ValidationError('enabled field must be a boolean value');
    }

    logger.info(`POST /rules/${id}/toggle called - ${enabled ? 'enabling' : 'disabling'} rule`, {
      rule_id: id,
      enabled,
      reason,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get current rule state first
      const currentRule = await opnsenseService.getFirewallRuleById(id);
      if (!currentRule) {
        throw new NotFoundError(`Firewall rule with ID ${id} not found`);
      }

      if (!currentRule.manageable) {
        throw new ValidationError('This rule cannot be modified (system rule or read-only)');
      }

      const previousState = currentRule.enabled;
      
      // Toggle the rule
      const result = await opnsenseService.toggleFirewallRule(id, enabled);

      await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'warning', {
        action: 'toggle_firewall_rule',
        rule_id: id,
        rule_description: currentRule.description,
        enabled,
        previous_state: previousState,
        reason: reason || 'No reason provided',
        user_id: getUserId(req)
      });

      logger.info(`Rule ${id} toggled successfully: ${previousState} -> ${enabled}`, {
        rule_id: id,
        enabled,
        previous_state: previousState,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: `Rule ${enabled ? 'enabled' : 'disabled'} successfully`,
        data: {
          rule_id: id,
          enabled,
          previous_state: previousState,
          config_applied: result.success,
          reason: reason || 'No reason provided'
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError || error instanceof ValidationError) {
        throw error;
      }
      
      logger.error(`Error toggling rule ${id}:`, { 
        error: error.message,
        rule_id: id,
        enabled,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to toggle firewall rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules:
 *   post:
 *     summary: Create a new firewall rule
 *     description: Creates a new firewall rule in OPNsense. The rule can be created as either a filter rule (integrated with WebUI) or automation rule (API-only).
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/FirewallRuleInput'
 *           examples:
 *             block_malicious:
 *               summary: Block malicious IP range
 *               value:
 *                 description: "Block known malicious IP range from threat intel"
 *                 interface: "wan"
 *                 action: "block"
 *                 enabled: true
 *                 source:
 *                   type: "network"
 *                   network: "192.168.100.0/24"
 *                 destination:
 *                   type: "any"
 *                 protocol: "any"
 *                 log: true
 *                 api_managed: false
 *             allow_management:
 *               summary: Allow management access
 *               value:
 *                 description: "Allow SSH access from management network"
 *                 interface: "lan"
 *                 action: "pass"
 *                 enabled: true
 *                 source:
 *                   type: "network"
 *                   network: "192.168.1.0/24"
 *                 destination:
 *                   type: "single"
 *                   address: "192.168.216.1"
 *                 protocol: "tcp"
 *                 destination_port: "22"
 *                 log: false
 *                 api_managed: false
 *     responses:
 *       201:
 *         description: Firewall rule created successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         uuid:
 *                           type: string
 *                           description: Unique identifier of the created rule
 *                           example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                         description:
 *                           type: string
 *                           example: "Block known malicious IP range"
 *                         interface:
 *                           type: string
 *                           example: "wan"
 *                         action:
 *                           type: string
 *                           example: "block"
 *                         enabled:
 *                           type: boolean
 *                           example: true
 *                         source_type:
 *                           type: string
 *                           example: "filter"
 *                         config_applied:
 *                           type: boolean
 *                           description: Whether the configuration was successfully applied
 *                           example: true
 *             examples:
 *               success:
 *                 summary: Rule created successfully
 *                 value:
 *                   success: true
 *                   message: "Firewall rule created successfully"
 *                   data:
 *                     uuid: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                     description: "Block known malicious IP range"
 *                     interface: "wan"
 *                     action: "block"
 *                     enabled: true
 *                     source_type: "filter"
 *                     config_applied: true
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       400:
 *         description: Invalid input data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             examples:
 *               validation_error:
 *                 summary: Validation failed
 *                 value:
 *                   success: false
 *                   error: "Validation failed"
 *                   details:
 *                     field: "interface"
 *                     message: "Invalid interface. Must be one of: wan, lan, opt1, opt2, opt3"
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       429:
 *         description: Rate limit exceeded
 *       500:
 *         description: Internal server error
 */
router.post(
  '/rules',
  validators.createFirewallRule,
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleData = {
      ...req.body,
      created_by: getUserId(req) || 1,
    };

    logger.info('POST /rules called - creating rule in OPNsense API', { 
      ruleData: { ...ruleData, created_by: getUserId(req) },
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const newRule = await opnsenseService.createFirewallRule(ruleData);

      await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
        action: 'create_firewall_rule',
        rule_id: newRule.uuid,
        description: newRule.description,
        interface: newRule.interface,
        action: newRule.action,
        enabled: newRule.enabled,
        source_type: newRule.source_type,
        user_id: getUserId(req)
      });

      logger.info('Firewall rule created successfully in OPNsense', {
        rule_id: newRule.uuid,
        description: newRule.description,
        source_type: newRule.source_type,
        user_id: getUserId(req)
      });

      res.status(201).json({
        success: true,
        message: 'Firewall rule created successfully',
        data: {
          uuid: newRule.uuid,
          description: newRule.description,
          interface: newRule.interface,
          action: newRule.action,
          enabled: newRule.enabled,
          source: newRule.source,
          destination: newRule.destination,
          protocol: newRule.protocol,
          source_type: newRule.source_type,
          manageable: newRule.manageable !== false,
          config_applied: true
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error creating rule in OPNsense API:', { 
        error: error.message,
        stack: error.stack,
        ruleData,
        user_id: getUserId(req)
      });
      
      if (error.message.includes('Invalid') || error.message.includes('required')) {
        throw new ValidationError(`Rule validation failed: ${error.message}`);
      }
      
      throw new Error(`Failed to create firewall rule in OPNsense: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   put:
 *     summary: Update an existing firewall rule
 *     description: Updates configuration of an existing firewall rule. Only manageable rules can be updated.
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *         example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 255
 *                 example: "Updated rule description"
 *               interface:
 *                 type: string
 *                 enum: [wan, lan, opt1, opt2, opt3, dmz]
 *                 example: "wan"
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *                 example: "block"
 *               enabled:
 *                 type: boolean
 *                 example: true
 *               source:
 *                 type: string
 *                 example: "192.168.100.0/24"
 *               destination:
 *                 type: string
 *                 example: "any"
 *               protocol:
 *                 type: string
 *                 enum: [tcp, udp, icmp, any]
 *                 example: "tcp"
 *               source_port:
 *                 type: string
 *                 example: "any"
 *               destination_port:
 *                 type: string
 *                 example: "80,443"
 *               log:
 *                 type: boolean
 *                 example: true
 *           examples:
 *             update_description:
 *               summary: Update rule description
 *               value:
 *                 description: "Updated: Block malicious IPs from new threat intel"
 *             update_ports:
 *               summary: Update destination ports
 *               value:
 *                 destination_port: "80,443,8080-8090"
 *                 log: true
 *     responses:
 *       200:
 *         description: Rule updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/FirewallRule'
 *       400:
 *         description: Invalid input data
 *       404:
 *         description: Rule not found or not manageable
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       500:
 *         description: Internal server error
 */
router.put(
  '/rules/:id',
  validators.idParam,
  validators.updateFirewallRule,
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = {
      ...req.body,
      updated_by: getUserId(req) || 1,
    };

    logger.info(`PUT /rules/${id} called - updating rule in OPNsense API`, { 
      rule_id: id,
      updates,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Verify rule exists and is manageable
      const existingRule = await opnsenseService.getFirewallRuleById(id);
      if (!existingRule) {
        throw new NotFoundError(`Firewall rule with ID ${id} not found`);
      }

      if (!existingRule.manageable) {
        throw new ValidationError('This rule cannot be modified (system rule or read-only)');
      }

      const updatedRule = await opnsenseService.updateFirewallRule(id, updates);

      await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
        action: 'update_firewall_rule',
        rule_id: id,
        description: updatedRule.description,
        changes: updates,
        previous_state: {
          description: existingRule.description,
          enabled: existingRule.enabled,
          action: existingRule.action
        },
        user_id: getUserId(req)
      });

      logger.info(`Firewall rule ${id} updated successfully in OPNsense`, {
        rule_id: id,
        description: updatedRule.description,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Firewall rule updated successfully',
        data: updatedRule,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError || error instanceof ValidationError) {
        throw error;
      }
      
      logger.error(`Error updating rule ${id} in OPNsense API:`, { 
        error: error.message,
        rule_id: id,
        updates,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to update firewall rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   delete:
 *     summary: Delete a firewall rule
 *     description: Permanently deletes a firewall rule from OPNsense. This action cannot be undone.
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *         example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Rule deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         rule_id:
 *                           type: string
 *                           example: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                         deleted:
 *                           type: boolean
 *                           example: true
 *                         config_applied:
 *                           type: boolean
 *                           example: true
 *             examples:
 *               success:
 *                 summary: Rule deleted successfully
 *                 value:
 *                   success: true
 *                   message: "Firewall rule deleted successfully"
 *                   data:
 *                     rule_id: "rule-123e4567-e89b-12d3-a456-426614174000"
 *                     deleted: true
 *                     config_applied: true
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       404:
 *         description: Rule not found or not manageable
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       500:
 *         description: Internal server error
 */
router.delete(
  '/rules/:id',
  validators.idParam,
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_DELETE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    logger.info(`DELETE /rules/${id} called - deleting rule from OPNsense API`, {
      rule_id: id,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Verify rule exists and get details for audit
      const existingRule = await opnsenseService.getFirewallRuleById(id);
      if (!existingRule) {
        throw new NotFoundError(`Firewall rule with ID ${id} not found`);
      }

      if (!existingRule.manageable) {
        throw new ValidationError('This rule cannot be deleted (system rule or read-only)');
      }

      const success = await opnsenseService.deleteFirewallRule(id);

      if (!success) {
        throw new Error('Delete operation failed');
      }

      await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', {
        action: 'delete_firewall_rule',
        rule_id: id,
        deleted_rule: {
          description: existingRule.description,
          interface: existingRule.interface,
          action: existingRule.action,
          enabled: existingRule.enabled,
          source_type: existingRule.source_type
        },
        user_id: getUserId(req)
      });

      logger.info(`Firewall rule ${id} deleted successfully from OPNsense`, {
        rule_id: id,
        description: existingRule.description,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Firewall rule deleted successfully',
        data: {
          rule_id: id,
          deleted: true,
          config_applied: true
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError || error instanceof ValidationError) {
        throw error;
      }
      
      logger.error(`Error deleting rule ${id} from OPNsense API:`, { 
        error: error.message,
        rule_id: id,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to delete firewall rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/stats:
 *   get:
 *     summary: Get comprehensive firewall statistics and system health
 *     description: Retrieves detailed statistics about firewall rules, system health, and OPNsense connectivity status
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Firewall statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/FirewallStats'
 *             examples:
 *               success:
 *                 summary: Complete statistics response
 *                 value:
 *                   success: true
 *                   message: "Firewall statistics retrieved successfully"
 *                   data:
 *                     total_rules: 42
 *                     enabled_rules: 35
 *                     disabled_rules: 7
 *                     by_interface:
 *                       wan: 15
 *                       lan: 20
 *                       dmz: 7
 *                     by_action:
 *                       pass: 25
 *                       block: 15
 *                       reject: 2
 *                     by_source_type:
 *                       filter: 30
 *                       automation: 10
 *                       config: 2
 *                     by_protocol:
 *                       tcp: 20
 *                       udp: 8
 *                       icmp: 2
 *                       any: 12
 *                     system_health:
 *                       opnsense_connected: true
 *                       api_response_time_ms: 245
 *                       last_config_apply: "2024-01-15T10:30:00Z"
 *                       overall_status: "healthy"
 *                       rate_limit_status:
 *                         active_operations: 3
 *                         total_requests_last_minute: 25
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       500:
 *         description: Internal server error or OPNsense connectivity issue
 */
router.get(
  '/stats',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    logger.info('GET /stats called - fetching comprehensive stats from OPNsense API', {
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get both rules and system health in parallel
      const [allRules, systemHealth] = await Promise.all([
        opnsenseService.getFirewallRules().catch(error => {
          logger.warn('Failed to get rules for stats', { error: error.message });
          return [];
        }),
        opnsenseService.getServiceHealth().catch(error => {
          logger.warn('Failed to get system health', { error: error.message });
          return { overall_status: 'unknown', error: error.message };
        })
      ]);

      // Calculate comprehensive statistics
      const stats = {
        total_rules: allRules.length,
        enabled_rules: allRules.filter(r => r.enabled).length,
        disabled_rules: allRules.filter(r => !r.enabled).length,
        by_interface: {},
        by_action: {},
        by_source_type: {},
        by_protocol: {},
        manageable_rules: allRules.filter(r => r.manageable).length,
        system_rules: allRules.filter(r => !r.manageable).length
      };

      // Group by various categories
      for (const rule of allRules) {
        // Count by interface
        stats.by_interface[rule.interface] = (stats.by_interface[rule.interface] || 0) + 1;
        
        // Count by action
        stats.by_action[rule.action] = (stats.by_action[rule.action] || 0) + 1;
        
        // Count by source type
        stats.by_source_type[rule.source_type] = (stats.by_source_type[rule.source_type] || 0) + 1;
        
        // Count by protocol
        const protocol = rule.protocol || 'any';
        stats.by_protocol[protocol] = (stats.by_protocol[protocol] || 0) + 1;
      }

      // Add system health information
      stats.system_health = {
        ...systemHealth,
        last_stats_update: new Date().toISOString()
      };

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'get_firewall_stats',
        total_rules: stats.total_rules,
        system_status: systemHealth.overall_status,
        user_id: getUserId(req)
      });

      logger.info('Firewall statistics retrieved successfully', {
        total_rules: stats.total_rules,
        enabled_rules: stats.enabled_rules,
        system_status: systemHealth.overall_status,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Firewall statistics retrieved successfully',
        data: stats,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error fetching firewall stats from OPNsense API:', { 
        error: error.message,
        stack: error.stack,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to retrieve firewall statistics: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/health:
 *   get:
 *     summary: Get detailed system health information
 *     description: Retrieves comprehensive health status of the OPNsense system and API connectivity
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System health retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         overall_status:
 *                           type: string
 *                           enum: [healthy, unhealthy, degraded, unknown]
 *                           example: "healthy"
 *                         components:
 *                           type: object
 *                           properties:
 *                             api_connectivity:
 *                               type: boolean
 *                               example: true
 *                             firewall_rules_accessible:
 *                               type: boolean
 *                               example: true
 *                             api_response_time_ms:
 *                               type: integer
 *                               example: 245
 *                         connection_test:
 *                           type: object
 *                           properties:
 *                             success:
 *                               type: boolean
 *                               example: true
 *                             response_time_ms:
 *                               type: integer
 *                               example: 150
 *                             api_version:
 *                               type: string
 *                               example: "24.1"
 *                             system_version:
 *                               type: string
 *                               example: "24.1.1"
 *                         rate_limit_status:
 *                           type: object
 *                           properties:
 *                             active_operations:
 *                               type: integer
 *                               example: 3
 *                             total_requests_last_minute:
 *                               type: integer
 *                               example: 25
 *             examples:
 *               healthy:
 *                 summary: System is healthy
 *                 value:
 *                   success: true
 *                   message: "System health retrieved successfully"
 *                   data:
 *                     overall_status: "healthy"
 *                     components:
 *                       api_connectivity: true
 *                       firewall_rules_accessible: true
 *                       api_response_time_ms: 245
 *                     connection_test:
 *                       success: true
 *                       response_time_ms: 150
 *                       api_version: "24.1"
 *                       system_version: "24.1.1"
 *                     rate_limit_status:
 *                       active_operations: 3
 *                       total_requests_last_minute: 25
 *                   timestamp: "2024-01-15T10:30:00Z"
 *       500:
 *         description: Unable to retrieve system health
 */
router.get(
  '/health',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    logger.info('GET /health called - checking OPNsense system health', {
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get detailed health information
      const [serviceHealth, connectionTest] = await Promise.all([
        opnsenseService.getServiceHealth(),
        opnsenseService.testConnection()
      ]);

      const healthData = {
        ...serviceHealth,
        connection_test: connectionTest,
        timestamp: new Date().toISOString()
      };

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'get_system_health',
        overall_status: serviceHealth.overall_status,
        api_connected: connectionTest.success,
        user_id: getUserId(req)
      });

      logger.info('System health retrieved successfully', {
        overall_status: serviceHealth.overall_status,
        api_connected: connectionTest.success,
        response_time: connectionTest.response_time_ms,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'System health retrieved successfully',
        data: healthData,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error retrieving system health:', { 
        error: error.message,
        user_id: getUserId(req)
      });
      
      // Still return partial health data even if there's an error
      res.status(200).json({
        success: true,
        message: 'Partial system health retrieved',
        data: {
          overall_status: 'unknown',
          error: error.message,
          timestamp: new Date().toISOString()
        },
        timestamp: new Date().toISOString()
      });
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/apply:
 *   post:
 *     summary: Apply pending firewall configuration changes
 *     description: Manually triggers the application of pending firewall configuration changes. This is automatically done after rule modifications, but can be triggered manually if needed.
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configuration applied successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         applied:
 *                           type: boolean
 *                           example: true
 *                         apply_time_ms:
 *                           type: integer
 *                           description: Time taken to apply configuration
 *                           example: 2500
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       500:
 *         description: Configuration apply failed
 */
router.post(
  '/apply',
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    logger.info('POST /apply called - applying firewall configuration', {
      user_id: getUserId(req)
    });

    try {
      const startTime = Date.now();
      const opnsenseService = new OpnsenseService(req.user);
      
      const success = await opnsenseService.applyConfigurationChanges();
      const applyTime = Date.now() - startTime;

      await auditLog(req, AUDITED_ACTIONS.CONFIG_APPLY, 'warning', {
        action: 'apply_firewall_config',
        success,
        apply_time_ms: applyTime,
        user_id: getUserId(req)
      });

      logger.info(`Firewall configuration applied successfully in ${applyTime}ms`, {
        apply_time_ms: applyTime,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Firewall configuration applied successfully',
        data: {
          applied: success,
          apply_time_ms: applyTime
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error applying firewall configuration:', { 
        error: error.message,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to apply firewall configuration: ${error.message}`);
    }
  })
);

module.exports = router;