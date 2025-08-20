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
 *     AutomationRule:
 *       type: object
 *       properties:
 *         uuid:
 *           type: string
 *           description: Unique identifier for the automation rule
 *           example: "auto-123e4567-e89b-12d3-a456-426614174000"
 *         description:
 *           type: string
 *           description: Human-readable description of the rule
 *           example: "Block malicious IPs via automation API"
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
 *         created_via:
 *           type: string
 *           enum: [API]
 *           description: How the rule was created (always API for automation)
 *           example: "API"
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
 *     AutomationRuleInput:
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
 */

/**
 * @swagger
 * /api/v1/firewall/automation/rules:
 *   get:
 *     summary: List automation firewall rules
 *     description: Retrieves firewall rules managed via automation API. These are separate from WebUI rules and are designed for programmatic management.
 *     tags: [Firewall Automation]
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
 *         description: Search term to filter rules by description
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
 *     responses:
 *       200:
 *         description: Automation rules retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Automation rules retrieved successfully"
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/AutomationRule'
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     current_page:
 *                       type: integer
 *                       example: 1
 *                     per_page:
 *                       type: integer
 *                       example: 20
 *                     total:
 *                       type: integer
 *                       example: 42
 *                     total_pages:
 *                       type: integer
 *                       example: 3
 *                 summary:
 *                   type: object
 *                   properties:
 *                     total_automation_rules:
 *                       type: integer
 *                       example: 42
 *                     enabled_rules:
 *                       type: integer
 *                       example: 35
 *                     by_interface:
 *                       type: object
 *                       example:
 *                         wan: 15
 *                         lan: 20
 *                     by_action:
 *                       type: object
 *                       example:
 *                         pass: 25
 *                         block: 15
 */
router.get(
  '/automation/rules',
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
      protocol
    } = req.query;

    logger.info('GET /automation/rules called - fetching automation rules only', { 
      page, 
      limit, 
      filters: { search, interfaceFilter, action, enabled, protocol },
      user_id: getUserId(req)
    });

    const filters = {
      interface: interfaceFilter,
      action,
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined,
      protocol,
      search,
      source_type: 'automation' // Force automation rules only
    };

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get automation rules specifically
      const allRules = await opnsenseService.getFirewallRules(filters);
      
      // Filter to ensure we only have automation rules
      const automationRules = allRules.filter(rule => 
        rule.source_type === 'automation' || rule.created_via === 'API'
      );
      
      // Apply pagination
      const pageNum = parseInt(page, 10);
      const limitNum = parseInt(limit, 10);
      const startIndex = (pageNum - 1) * limitNum;
      const endIndex = startIndex + limitNum;
      const paginatedRules = automationRules.slice(startIndex, endIndex);

      const pagination = {
        current_page: pageNum,
        per_page: limitNum,
        total: automationRules.length,
        total_pages: Math.ceil(automationRules.length / limitNum),
        has_next: pageNum < Math.ceil(automationRules.length / limitNum),
        has_prev: pageNum > 1,
      };

      // Summary for automation rules only
      const summary = {
        total_automation_rules: automationRules.length,
        enabled_rules: automationRules.filter(r => r.enabled).length,
        disabled_rules: automationRules.filter(r => !r.enabled).length,
        by_interface: {},
        by_action: {},
        by_protocol: {}
      };

      for (const rule of automationRules) {
        summary.by_interface[rule.interface] = (summary.by_interface[rule.interface] || 0) + 1;
        summary.by_action[rule.action] = (summary.by_action[rule.action] || 0) + 1;
        summary.by_protocol[rule.protocol || 'any'] = (summary.by_protocol[rule.protocol || 'any'] || 0) + 1;
      }

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'list_automation_rules',
        filters,
        total_count: automationRules.length,
        returned_count: paginatedRules.length,
        user_id: getUserId(req)
      });

      logger.info(`Automation rules retrieved: ${automationRules.length} total, ${paginatedRules.length} returned`, {
        user_id: getUserId(req),
        filters
      });

      res.json({
        success: true,
        message: 'Automation rules retrieved successfully',
        data: paginatedRules,
        pagination,
        summary,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error fetching automation rules:', { 
        error: error.message, 
        filters: req.query,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to retrieve automation rules: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/rules/{id}:
 *   get:
 *     summary: Get specific automation rule by ID
 *     description: Retrieves detailed information about a specific automation rule
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *         example: "auto-123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Automation rule retrieved successfully
 *       404:
 *         description: Automation rule not found
 */
router.get(
  '/automation/rules/:id',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    logger.info(`GET /automation/rules/${id} called`, {
      rule_id: id,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const rule = await opnsenseService.getFirewallRuleById(id);

      if (!rule) {
        throw new NotFoundError(`Automation rule with ID ${id} not found`);
      }

      // Verify it's an automation rule
      if (rule.source_type !== 'automation' && rule.created_via !== 'API') {
        throw new NotFoundError(`Rule ${id} is not an automation rule`);
      }

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'get_automation_rule',
        rule_id: id,
        rule_description: rule.description,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Automation rule retrieved successfully',
        data: rule,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      
      logger.error(`Error fetching automation rule ${id}:`, { 
        error: error.message,
        rule_id: id,
        user_id: getUserId(req)
      });
      
      throw new NotFoundError(`Automation rule with ID ${id} not found or inaccessible`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/rules:
 *   post:
 *     summary: Create a new automation rule
 *     description: Creates a new firewall rule via the automation API. These rules are managed separately from WebUI rules.
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AutomationRuleInput'
 *           examples:
 *             block_malicious:
 *               summary: Block malicious IP range
 *               value:
 *                 description: "AUTOMATION: Block known malicious IP range"
 *                 interface: "wan"
 *                 action: "block"
 *                 enabled: true
 *                 source: "192.168.100.0/24"
 *                 destination: "any"
 *                 protocol: "any"
 *                 log: true
 *             allow_api_access:
 *               summary: Allow API access
 *               value:
 *                 description: "AUTOMATION: Allow API access from monitoring"
 *                 interface: "lan"
 *                 action: "pass"
 *                 enabled: true
 *                 source: "192.168.1.100"
 *                 destination: "192.168.216.1"
 *                 protocol: "tcp"
 *                 destination_port: "443"
 *                 log: false
 *     responses:
 *       201:
 *         description: Automation rule created successfully
 */
router.post(
  '/automation/rules',
  validators.createFirewallRule,
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleData = {
      ...req.body,
      api_managed: true, // Force automation rule
      source_type: 'automation',
      created_by: getUserId(req) || 1,
      // Prefix description to indicate automation
      description: req.body.description.startsWith('AUTOMATION:') 
        ? req.body.description 
        : `AUTOMATION: ${req.body.description}`
    };

    logger.info('POST /automation/rules called - creating automation rule', { 
      ruleData: { ...ruleData, created_by: getUserId(req) },
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const newRule = await opnsenseService.createAutomationRule(ruleData);

      await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
        action: 'create_automation_rule',
        rule_id: newRule.uuid,
        description: newRule.description,
        interface: newRule.interface,
        action: newRule.action,
        enabled: newRule.enabled,
        user_id: getUserId(req)
      });

      logger.info('Automation rule created successfully', {
        rule_id: newRule.uuid,
        description: newRule.description,
        user_id: getUserId(req)
      });

      res.status(201).json({
        success: true,
        message: 'Automation rule created successfully',
        data: {
          uuid: newRule.uuid,
          description: newRule.description,
          interface: newRule.interface,
          action: newRule.action,
          enabled: newRule.enabled,
          source: newRule.source,
          destination: newRule.destination,
          protocol: newRule.protocol,
          source_type: 'automation',
          created_via: 'API',
          config_applied: true
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error creating automation rule:', { 
        error: error.message,
        ruleData,
        user_id: getUserId(req)
      });
      
      if (error.message.includes('Invalid') || error.message.includes('required')) {
        throw new ValidationError(`Automation rule validation failed: ${error.message}`);
      }
      
      throw new Error(`Failed to create automation rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/rules/{id}/toggle:
 *   post:
 *     summary: Toggle automation rule enabled/disabled status
 *     description: Enable or disable a specific automation rule
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
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
 *               reason:
 *                 type: string
 *                 description: Reason for the change
 *     responses:
 *       200:
 *         description: Rule toggled successfully
 *       404:
 *         description: Rule not found or not an automation rule
 */
router.post(
  '/automation/rules/:id/toggle',
  validators.idParam,
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { enabled, reason } = req.body;

    if (typeof enabled !== 'boolean') {
      throw new ValidationError('enabled field must be a boolean value');
    }

    logger.info(`POST /automation/rules/${id}/toggle called`, {
      rule_id: id,
      enabled,
      reason,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Verify it's an automation rule
      const currentRule = await opnsenseService.getFirewallRuleById(id);
      if (!currentRule) {
        throw new NotFoundError(`Automation rule with ID ${id} not found`);
      }

      if (currentRule.source_type !== 'automation' && currentRule.created_via !== 'API') {
        throw new ValidationError('This rule is not an automation rule');
      }

      const previousState = currentRule.enabled;
      const result = await opnsenseService.toggleAutomationRule(id, enabled);

      await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'warning', {
        action: 'toggle_automation_rule',
        rule_id: id,
        rule_description: currentRule.description,
        enabled,
        previous_state: previousState,
        reason: reason || 'No reason provided',
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: `Automation rule ${enabled ? 'enabled' : 'disabled'} successfully`,
        data: {
          rule_id: id,
          enabled,
          previous_state: previousState,
          config_applied: result.success || true,
          reason: reason || 'No reason provided'
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError || error instanceof ValidationError) {
        throw error;
      }
      
      logger.error(`Error toggling automation rule ${id}:`, { 
        error: error.message,
        rule_id: id,
        enabled,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to toggle automation rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/rules/{id}:
 *   put:
 *     summary: Update an existing automation rule
 *     description: Updates configuration of an existing automation rule
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *                 example: "Updated automation rule description"
 *               interface:
 *                 type: string
 *                 enum: [wan, lan, opt1, opt2, opt3, dmz]
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *               enabled:
 *                 type: boolean
 *               source:
 *                 type: string
 *               destination:
 *                 type: string
 *               protocol:
 *                 type: string
 *                 enum: [tcp, udp, icmp, any]
 *               source_port:
 *                 type: string
 *               destination_port:
 *                 type: string
 *               log:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Rule updated successfully
 *       404:
 *         description: Rule not found or not an automation rule
 */
router.put(
  '/automation/rules/:id',
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

    logger.info(`PUT /automation/rules/${id} called`, { 
      rule_id: id,
      updates,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Verify it's an automation rule
      const existingRule = await opnsenseService.getFirewallRuleById(id);
      if (!existingRule) {
        throw new NotFoundError(`Automation rule with ID ${id} not found`);
      }

      if (existingRule.source_type !== 'automation' && existingRule.created_via !== 'API') {
        throw new ValidationError('This rule is not an automation rule');
      }

      const updatedRule = await opnsenseService.updateAutomationRule(id, updates);

      await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
        action: 'update_automation_rule',
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

      res.json({
        success: true,
        message: 'Automation rule updated successfully',
        data: updatedRule,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      if (error instanceof NotFoundError || error instanceof ValidationError) {
        throw error;
      }
      
      logger.error(`Error updating automation rule ${id}:`, { 
        error: error.message,
        rule_id: id,
        updates,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to update automation rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/rules/{id}:
 *   delete:
 *     summary: Delete an automation rule
 *     description: Permanently deletes an automation rule
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Rule UUID or identifier
 *     responses:
 *       200:
 *         description: Rule deleted successfully
 *       404:
 *         description: Rule not found or not an automation rule
 */
router.delete(
  '/automation/rules/:id',
  validators.idParam,
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_DELETE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    logger.info(`DELETE /automation/rules/${id} called`, {
      rule_id: id,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Verify it's an automation rule
      const existingRule = await opnsenseService.getFirewallRuleById(id);
      if (!existingRule) {
        throw new NotFoundError(`Automation rule with ID ${id} not found`);
      }

      if (existingRule.source_type !== 'automation' && existingRule.created_via !== 'API') {
        throw new ValidationError('This rule is not an automation rule');
      }

      const success = await opnsenseService.deleteAutomationRule(id);

      if (!success) {
        throw new Error('Delete operation failed');
      }

      await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', {
        action: 'delete_automation_rule',
        rule_id: id,
        deleted_rule: {
          description: existingRule.description,
          interface: existingRule.interface,
          action: existingRule.action,
          enabled: existingRule.enabled
        },
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Automation rule deleted successfully',
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
      
      logger.error(`Error deleting automation rule ${id}:`, { 
        error: error.message,
        rule_id: id,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to delete automation rule: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/stats:
 *   get:
 *     summary: Get automation rules statistics
 *     description: Retrieves statistics specifically for automation-managed firewall rules
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Automation statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Automation statistics retrieved successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     total_automation_rules:
 *                       type: integer
 *                       example: 25
 *                     enabled_rules:
 *                       type: integer
 *                       example: 20
 *                     disabled_rules:
 *                       type: integer
 *                       example: 5
 *                     by_interface:
 *                       type: object
 *                       example:
 *                         wan: 15
 *                         lan: 10
 *                     by_action:
 *                       type: object
 *                       example:
 *                         block: 15
 *                         pass: 8
 *                         reject: 2
 *                     by_protocol:
 *                       type: object
 *                       example:
 *                         tcp: 12
 *                         udp: 5
 *                         any: 8
 *                     automation_health:
 *                       type: object
 *                       properties:
 *                         api_accessible:
 *                           type: boolean
 *                           example: true
 *                         last_rule_created:
 *                           type: string
 *                           format: date-time
 *                           example: "2024-01-15T10:30:00Z"
 */
router.get(
  '/automation/stats',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    logger.info('GET /automation/stats called', {
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get all rules and filter for automation only
      const allRules = await opnsenseService.getFirewallRules();
      const automationRules = allRules.filter(rule => 
        rule.source_type === 'automation' || rule.created_via === 'API'
      );

      // Calculate automation-specific statistics
      const stats = {
        total_automation_rules: automationRules.length,
        enabled_rules: automationRules.filter(r => r.enabled).length,
        disabled_rules: automationRules.filter(r => !r.enabled).length,
        by_interface: {},
        by_action: {},
        by_protocol: {},
        rules_with_logging: automationRules.filter(r => r.log).length
      };

      // Group by categories
      for (const rule of automationRules) {
        stats.by_interface[rule.interface] = (stats.by_interface[rule.interface] || 0) + 1;
        stats.by_action[rule.action] = (stats.by_action[rule.action] || 0) + 1;
        const protocol = rule.protocol || 'any';
        stats.by_protocol[protocol] = (stats.by_protocol[protocol] || 0) + 1;
      }

      // Get automation health
      const systemHealth = await opnsenseService.getServiceHealth().catch(error => {
        logger.warn('Failed to get system health for automation stats', { error: error.message });
        return { overall_status: 'unknown' };
      });

      stats.automation_health = {
        api_accessible: systemHealth.overall_status === 'healthy',
        system_status: systemHealth.overall_status,
        last_rule_created: automationRules.length > 0 
          ? automationRules.sort((a, b) => new Date(b.created) - new Date(a.created))[0].created
          : null,
        api_response_time_ms: systemHealth.components?.api_response_time_ms || null
      };

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'get_automation_stats',
        total_automation_rules: stats.total_automation_rules,
        user_id: getUserId(req)
      });

      logger.info('Automation statistics retrieved successfully', {
        total_automation_rules: stats.total_automation_rules,
        enabled_rules: stats.enabled_rules,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Automation statistics retrieved successfully',
        data: stats,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error fetching automation statistics:', { 
        error: error.message,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to retrieve automation statistics: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/apply:
 *   post:
 *     summary: Apply automation rule configuration changes
 *     description: Manually triggers the application of pending automation rule configuration changes
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configuration applied successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Automation configuration applied successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     applied:
 *                       type: boolean
 *                       example: true
 *                     apply_time_ms:
 *                       type: integer
 *                       example: 2500
 *                     automation_rules_count:
 *                       type: integer
 *                       example: 25
 */
router.post(
  '/automation/apply',
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    logger.info('POST /automation/apply called', {
      user_id: getUserId(req)
    });

    try {
      const startTime = Date.now();
      const opnsenseService = new OpnsenseService(req.user);
      
      // Apply configuration changes
      const success = await opnsenseService.applyConfigurationChanges();
      const applyTime = Date.now() - startTime;

      // Get automation rules count for context
      const allRules = await opnsenseService.getFirewallRules().catch(() => []);
      const automationRulesCount = allRules.filter(rule => 
        rule.source_type === 'automation' || rule.created_via === 'API'
      ).length;

      await auditLog(req, AUDITED_ACTIONS.CONFIG_APPLY, 'warning', {
        action: 'apply_automation_config',
        success,
        apply_time_ms: applyTime,
        automation_rules_count: automationRulesCount,
        user_id: getUserId(req)
      });

      logger.info(`Automation configuration applied successfully in ${applyTime}ms`, {
        apply_time_ms: applyTime,
        automation_rules_count: automationRulesCount,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Automation configuration applied successfully',
        data: {
          applied: success,
          apply_time_ms: applyTime,
          automation_rules_count: automationRulesCount
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error applying automation configuration:', { 
        error: error.message,
        user_id: getUserId(req)
      });
      
      throw new Error(`Failed to apply automation configuration: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/bulk:
 *   post:
 *     summary: Bulk operations on automation rules
 *     description: Perform bulk operations like enable/disable/delete on multiple automation rules
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - operation
 *               - rule_ids
 *             properties:
 *               operation:
 *                 type: string
 *                 enum: [enable, disable, delete]
 *                 description: Operation to perform on the rules
 *                 example: "disable"
 *               rule_ids:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of rule UUIDs to operate on
 *                 example: ["auto-123", "auto-456", "auto-789"]
 *               reason:
 *                 type: string
 *                 description: Reason for the bulk operation
 *                 example: "Emergency security response"
 *           examples:
 *             bulk_disable:
 *               summary: Disable multiple rules
 *               value:
 *                 operation: "disable"
 *                 rule_ids: ["auto-123", "auto-456"]
 *                 reason: "Security incident response"
 *             bulk_delete:
 *               summary: Delete multiple rules
 *               value:
 *                 operation: "delete"
 *                 rule_ids: ["auto-789", "auto-101"]
 *                 reason: "Cleanup obsolete rules"
 *     responses:
 *       200:
 *         description: Bulk operation completed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Bulk operation completed"
 *                 data:
 *                   type: object
 *                   properties:
 *                     operation:
 *                       type: string
 *                       example: "disable"
 *                     total_requested:
 *                       type: integer
 *                       example: 3
 *                     successful:
 *                       type: integer
 *                       example: 2
 *                     failed:
 *                       type: integer
 *                       example: 1
 *                     results:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           rule_id:
 *                             type: string
 *                           success:
 *                             type: boolean
 *                           error:
 *                             type: string
 *                     config_applied:
 *                       type: boolean
 *                       example: true
 */
router.post(
  '/automation/bulk',
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { operation, rule_ids, reason } = req.body;

    // Validate input
    if (!operation || !['enable', 'disable', 'delete'].includes(operation)) {
      throw new ValidationError('operation must be one of: enable, disable, delete');
    }

    if (!rule_ids || !Array.isArray(rule_ids) || rule_ids.length === 0) {
      throw new ValidationError('rule_ids must be a non-empty array');
    }

    if (rule_ids.length > 50) {
      throw new ValidationError('Maximum 50 rules per bulk operation');
    }

    logger.info(`POST /automation/bulk called - ${operation} on ${rule_ids.length} rules`, {
      operation,
      rule_count: rule_ids.length,
      reason,
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const results = [];
      let successful = 0;
      let failed = 0;

      // Process each rule
      for (const ruleId of rule_ids) {
        try {
          // Verify it's an automation rule first
          const rule = await opnsenseService.getFirewallRuleById(ruleId);
          
          if (!rule) {
            results.push({
              rule_id: ruleId,
              success: false,
              error: 'Rule not found'
            });
            failed++;
            continue;
          }

          if (rule.source_type !== 'automation' && rule.created_via !== 'API') {
            results.push({
              rule_id: ruleId,
              success: false,
              error: 'Not an automation rule'
            });
            failed++;
            continue;
          }

          // Perform the operation
          let operationResult;
          switch (operation) {
            case 'enable':
              operationResult = await opnsenseService.toggleAutomationRule(ruleId, true);
              break;
            case 'disable':
              operationResult = await opnsenseService.toggleAutomationRule(ruleId, false);
              break;
            case 'delete':
              operationResult = await opnsenseService.deleteAutomationRule(ruleId);
              break;
          }

          results.push({
            rule_id: ruleId,
            success: true,
            previous_state: operation !== 'delete' ? rule.enabled : null
          });
          successful++;

        } catch (error) {
          logger.warn(`Bulk operation failed for rule ${ruleId}:`, { 
            error: error.message,
            operation,
            rule_id: ruleId
          });
          
          results.push({
            rule_id: ruleId,
            success: false,
            error: error.message
          });
          failed++;
        }
      }

      // Apply configuration if any operations succeeded
      let configApplied = false;
      if (successful > 0) {
        try {
          await opnsenseService.applyConfigurationChanges();
          configApplied = true;
        } catch (error) {
          logger.error('Failed to apply configuration after bulk operation:', error.message);
        }
      }

      await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'warning', {
        action: 'bulk_automation_operation',
        operation,
        total_requested: rule_ids.length,
        successful,
        failed,
        reason: reason || 'No reason provided',
        user_id: getUserId(req)
      });

      logger.info(`Bulk automation operation completed: ${successful}/${rule_ids.length} successful`, {
        operation,
        successful,
        failed,
        config_applied: configApplied,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: `Bulk ${operation} operation completed`,
        data: {
          operation,
          total_requested: rule_ids.length,
          successful,
          failed,
          results,
          config_applied: configApplied,
          reason: reason || 'No reason provided'
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error in bulk automation operation:', { 
        error: error.message,
        operation,
        rule_count: rule_ids.length,
        user_id: getUserId(req)
      });
      
      throw new Error(`Bulk automation operation failed: ${error.message}`);
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/automation/health:
 *   get:
 *     summary: Get automation-specific health information
 *     description: Retrieves health status specifically for automation API functionality
 *     tags: [Firewall Automation]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Automation health retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Automation health retrieved successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     automation_status:
 *                       type: string
 *                       enum: [healthy, degraded, unhealthy]
 *                       example: "healthy"
 *                     automation_api_accessible:
 *                       type: boolean
 *                       example: true
 *                     automation_rules_count:
 *                       type: integer
 *                       example: 25
 *                     last_automation_activity:
 *                       type: string
 *                       format: date-time
 *                       example: "2024-01-15T10:30:00Z"
 *                     rate_limit_status:
 *                       type: object
 *                       properties:
 *                         automation_requests_last_minute:
 *                           type: integer
 *                           example: 15
 */
router.get(
  '/automation/health',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    logger.info('GET /automation/health called', {
      user_id: getUserId(req)
    });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      
      // Get system health and automation-specific data
      const [systemHealth, allRules] = await Promise.all([
        opnsenseService.getServiceHealth().catch(error => ({
          overall_status: 'unknown',
          error: error.message
        })),
        opnsenseService.getFirewallRules().catch(() => [])
      ]);

      // Filter for automation rules
      const automationRules = allRules.filter(rule => 
        rule.source_type === 'automation' || rule.created_via === 'API'
      );

      // Determine automation-specific status
      let automationStatus = 'healthy';
      if (systemHealth.overall_status === 'unhealthy') {
        automationStatus = 'unhealthy';
      } else if (systemHealth.overall_status === 'degraded' || systemHealth.overall_status === 'unknown') {
        automationStatus = 'degraded';
      }

      // Get rate limit info specifically for automation operations
      const rateLimitStatus = systemHealth.rate_limit_status || {};
      const automationOperations = [
        'create_automation_rule',
        'update_automation_rule', 
        'delete_automation_rule',
        'get_automation_rule'
      ];
      
      let automationRequestsLastMinute = 0;
      for (const op of automationOperations) {
        automationRequestsLastMinute += rateLimitStatus.operations?.[op] || 0;
      }

      const healthData = {
        automation_status: automationStatus,
        automation_api_accessible: systemHealth.components?.api_connectivity || false,
        automation_rules_count: automationRules.length,
        enabled_automation_rules: automationRules.filter(r => r.enabled).length,
        last_automation_activity: automationRules.length > 0 
          ? automationRules.sort((a, b) => new Date(b.created) - new Date(a.created))[0].created
          : null,
        system_response_time_ms: systemHealth.components?.api_response_time_ms || null,
        rate_limit_status: {
          automation_requests_last_minute: automationRequestsLastMinute,
          total_operations_tracked: Object.keys(rateLimitStatus.operations || {}).length
        },
        underlying_system: {
          overall_status: systemHealth.overall_status,
          api_connectivity: systemHealth.components?.api_connectivity,
          firewall_accessible: systemHealth.components?.firewall_rules_accessible
        },
        timestamp: new Date().toISOString()
      };

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'get_automation_health',
        automation_status: automationStatus,
        rules_count: automationRules.length,
        user_id: getUserId(req)
      });

      logger.info('Automation health retrieved successfully', {
        automation_status: automationStatus,
        rules_count: automationRules.length,
        api_accessible: healthData.automation_api_accessible,
        user_id: getUserId(req)
      });

      res.json({
        success: true,
        message: 'Automation health retrieved successfully',
        data: healthData,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.error('Error retrieving automation health:', { 
        error: error.message,
        user_id: getUserId(req)
      });
      
      // Return partial health data even on error
      res.status(200).json({
        success: true,
        message: 'Partial automation health retrieved',
        data: {
          automation_status: 'unknown',
          automation_api_accessible: false,
          error: error.message,
          timestamp: new Date().toISOString()
        },
        timestamp: new Date().toISOString()
      });
    }
  })
);

module.exports = router;