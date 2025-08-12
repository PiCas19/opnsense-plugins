const express = require('express');
const { authenticate, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { auditLog, AUDITED_ACTIONS } = require('../middleware/audit');
const { rateLimiters } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError, ValidationError } = require('../middleware/errorHandler');
const OpnsenseService = require('../services/OpnsenseService');
const RuleService = require('../services/RuleService');
const Rule = require('../models/Rule');
const logger = require('../utils/logger');

const router = express.Router();

// Apply firewall-specific rate limiting and authentication
router.use(rateLimiters.firewall);
router.use(authenticate);

/**
 * @swagger
 * /api/v1/firewall/rules:
 *   get:
 *     summary: List firewall rules with pagination and filtering
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
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: interface
 *         schema:
 *           type: string
 *           enum: [wan, lan, dmz, opt1, opt2]
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *           enum: [pass, block, reject]
 *       - in: query
 *         name: enabled
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: protocol
 *         schema:
 *           type: string
 *           enum: [tcp, udp, icmp, any]
 *     responses:
 *       200:
 *         description: Rules retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/FirewallRule'
 *                 pagination:
 *                   $ref: '#/components/schemas/Pagination'
 */
router.get('/rules',
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
    
    const ruleService = new RuleService(req.user);
    
    const filters = {
      search,
      interface: interfaceFilter,
      action,
      enabled: enabled !== undefined ? enabled === 'true' : undefined,
      protocol
    };
    
    const result = await ruleService.getRules(
      parseInt(page),
      parseInt(limit),
      filters
    );
    
    await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
      action: 'list_firewall_rules',
      filters: filters,
      count: result.data.length
    });
    
    res.json({
      success: true,
      message: 'Firewall rules retrieved successfully',
      data: result.data,
      pagination: result.pagination
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   get:
 *     summary: Get specific firewall rule by ID
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Rule retrieved successfully
 *       404:
 *         description: Rule not found
 */
router.get('/rules/:id',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const rule = await Rule.findByPk(id, {
      include: [{
        model: require('../models/User'),
        as: 'creator',
        attributes: ['username']
      }]
    });
    
    if (!rule) {
      throw new NotFoundError('Firewall rule not found');
    }
    
    res.json({
      success: true,
      message: 'Firewall rule retrieved successfully',
      data: rule
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules:
 *   post:
 *     summary: Create a new firewall rule
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - description
 *               - interface
 *               - action
 *               - protocol
 *               - source
 *               - destination
 *             properties:
 *               description:
 *                 type: string
 *                 maxLength: 255
 *               interface:
 *                 type: string
 *                 enum: [wan, lan, dmz, opt1, opt2]
 *               direction:
 *                 type: string
 *                 enum: [in, out]
 *                 default: in
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *               protocol:
 *                 type: string
 *                 enum: [tcp, udp, icmp, any]
 *               source:
 *                 type: object
 *                 properties:
 *                   type:
 *                     type: string
 *                     enum: [any, single, network, alias]
 *                   address:
 *                     type: string
 *                   network:
 *                     type: string
 *                   port:
 *                     type: integer
 *               destination:
 *                 type: object
 *                 properties:
 *                   type:
 *                     type: string
 *                     enum: [any, single, network, alias]
 *                   address:
 *                     type: string
 *                   network:
 *                     type: string
 *                   port:
 *                     type: integer
 *               enabled:
 *                 type: boolean
 *                 default: true
 *               log:
 *                 type: boolean
 *                 default: false
 *               sequence:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 9999
 *     responses:
 *       201:
 *         description: Rule created successfully
 *       400:
 *         description: Validation error
 */
router.post('/rules',
  validators.createFirewallRule,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleData = {
      ...req.body,
      created_by: req.user.id,
      sync_status: 'pending'
    };
    
    const ruleService = new RuleService(req.user);
    const rule = await ruleService.createRule(ruleData);
    
    // Attempt to sync with OPNsense
    try {
      const opnsenseService = new OpnsenseService();
      const opnsenseRuleId = await opnsenseService.createRule(rule);
      
      await rule.update({
        opnsense_uuid: opnsenseRuleId,
        sync_status: 'synced',
        last_synced_at: new Date()
      });
      
      logger.info('Rule created and synced with OPNsense', {
        rule_id: rule.id,
        opnsense_uuid: opnsenseRuleId,
        user_id: req.user.id
      });
    } catch (syncError) {
      logger.error('Failed to sync rule with OPNsense', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: req.user.id
      });
      
      await rule.update({
        sync_status: 'failed',
        sync_error: syncError.message
      });
    }
    
    await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      interface: rule.interface,
      action: rule.action
    });
    
    res.status(201).json({
      success: true,
      message: 'Firewall rule created successfully',
      data: {
        id: rule.id,
        uuid: rule.uuid,
        description: rule.description,
        sync_status: rule.sync_status
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   put:
 *     summary: Update an existing firewall rule
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *               interface:
 *                 type: string
 *                 enum: [wan, lan, dmz, opt1, opt2]
 *               action:
 *                 type: string
 *                 enum: [pass, block, reject]
 *               protocol:
 *                 type: string
 *                 enum: [tcp, udp, icmp, any]
 *               source:
 *                 type: object
 *               destination:
 *                 type: object
 *               enabled:
 *                 type: boolean
 *               log:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Rule updated successfully
 *       404:
 *         description: Rule not found
 */
router.put('/rules/:id',
  validators.idParam,
  validators.updateFirewallRule,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = {
      ...req.body,
      updated_by: req.user.id
    };
    
    const ruleService = new RuleService(req.user);
    const rule = await ruleService.updateRule(id, updates);
    
    // Attempt to sync with OPNsense
    try {
      const opnsenseService = new OpnsenseService();
      await opnsenseService.updateRule(rule.opnsense_uuid, rule);
      
      await rule.update({
        sync_status: 'synced',
        last_synced_at: new Date(),
        sync_error: null
      });
      
      logger.info('Rule updated and synced with OPNsense', {
        rule_id: rule.id,
        user_id: req.user.id
      });
    } catch (syncError) {
      logger.error('Failed to sync updated rule with OPNsense', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: req.user.id
      });
      
      await rule.update({
        sync_status: 'failed',
        sync_error: syncError.message
      });
    }
    
    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      changes: updates
    });
    
    res.json({
      success: true,
      message: 'Firewall rule updated successfully',
      data: {
        id: rule.id,
        sync_status: rule.sync_status
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}/toggle:
 *   patch:
 *     summary: Enable/disable a firewall rule
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
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
 *               apply_immediately:
 *                 type: boolean
 *                 default: false
 *     responses:
 *       200:
 *         description: Rule status changed successfully
 *       404:
 *         description: Rule not found
 */
router.patch('/rules/:id/toggle',
  validators.idParam,
  validators.toggleFirewallRule,
  authorize(PERMISSIONS.FIREWALL_TOGGLE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { enabled, apply_immediately = false } = req.body;
    
    const rule = await Rule.findByPk(id);
    if (!rule) {
      throw new NotFoundError('Firewall rule not found');
    }
    
    const previousState = rule.enabled;
    
    await rule.update({
      enabled,
      updated_by: req.user.id,
      sync_status: 'pending'
    });
    
    // Sync with OPNsense
    try {
      const opnsenseService = new OpnsenseService();
      await opnsenseService.toggleRule(rule.opnsense_uuid, enabled);
      
      if (apply_immediately) {
        await opnsenseService.applyChanges();
      }
      
      await rule.update({
        sync_status: 'synced',
        last_synced_at: new Date(),
        sync_error: null
      });
      
      logger.info(`Rule ${enabled ? 'enabled' : 'disabled'}`, {
        rule_id: rule.id,
        description: rule.description,
        user_id: req.user.id,
        applied: apply_immediately
      });
    } catch (syncError) {
      logger.error('Failed to sync rule toggle with OPNsense', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: req.user.id
      });
      
      await rule.update({
        sync_status: 'failed',
        sync_error: syncError.message
      });
    }
    
    await auditLog(req, AUDITED_ACTIONS.RULE_TOGGLE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      previous_state: previousState,
      new_state: enabled,
      applied_immediately: apply_immediately
    });
    
    res.json({
      success: true,
      message: `Rule ${enabled ? 'enabled' : 'disabled'} successfully`,
      data: {
        id: rule.id,
        enabled: rule.enabled,
        sync_status: rule.sync_status,
        applied: apply_immediately
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   delete:
 *     summary: Delete a firewall rule
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Rule deleted successfully
 *       404:
 *         description: Rule not found
 */
router.delete('/rules/:id',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_DELETE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const rule = await Rule.findByPk(id);
    if (!rule) {
      throw new NotFoundError('Firewall rule not found');
    }
    
    // Store rule info for audit before deletion
    const ruleInfo = {
      id: rule.id,
      description: rule.description,
      interface: rule.interface,
      action: rule.action,
      opnsense_uuid: rule.opnsense_uuid
    };
    
    // Delete from OPNsense first
    try {
      if (rule.opnsense_uuid) {
        const opnsenseService = new OpnsenseService();
        await opnsenseService.deleteRule(rule.opnsense_uuid);
        
        logger.info('Rule deleted from OPNsense', {
          rule_id: rule.id,
          opnsense_uuid: rule.opnsense_uuid,
          user_id: req.user.id
        });
      }
    } catch (syncError) {
      logger.warn('Failed to delete rule from OPNsense, continuing with local deletion', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: req.user.id
      });
    }
    
    // Soft delete from local database
    await rule.destroy();
    
    await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', {
      rule_id: ruleInfo.id,
      description: ruleInfo.description,
      interface: ruleInfo.interface,
      action: ruleInfo.action
    });
    
    res.json({
      success: true,
      message: 'Firewall rule deleted successfully'
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/bulk:
 *   patch:
 *     summary: Perform bulk operations on multiple rules
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - rule_ids
 *               - operation
 *             properties:
 *               rule_ids:
 *                 type: array
 *                 items:
 *                   type: integer
 *                 minItems: 1
 *                 maxItems: 50
 *               operation:
 *                 type: string
 *                 enum: [enable, disable, delete]
 *               apply_immediately:
 *                 type: boolean
 *                 default: false
 *     responses:
 *       200:
 *         description: Bulk operation completed
 *       400:
 *         description: Invalid operation or parameters
 */
router.patch('/rules/bulk',
  validators.bulkFirewallOperation,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { rule_ids, operation, apply_immediately = false } = req.body;
    
    const ruleService = new RuleService(req.user);
    const result = await ruleService.bulkOperation(rule_ids, operation, apply_immediately);
    
    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      bulk_operation: operation,
      rule_count: rule_ids.length,
      rule_ids: rule_ids,
      applied_immediately: apply_immediately
    });
    
    res.json({
      success: true,
      message: `Bulk ${operation} operation completed successfully`,
      data: result
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/sync:
 *   post:
 *     summary: Sync all pending rules with OPNsense
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sync operation completed
 */
router.post('/rules/sync',
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleService = new RuleService(req.user);
    const result = await ruleService.syncPendingRules();
    
    await auditLog(req, AUDITED_ACTIONS.SYSTEM_ACCESS, 'info', {
      action: 'sync_rules',
      synced_count: result.synced,
      failed_count: result.failed,
      total_pending: result.total
    });
    
    res.json({
      success: true,
      message: 'Rule synchronization completed',
      data: result
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/apply:
 *   post:
 *     summary: Apply firewall configuration changes
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configuration applied successfully
 *       500:
 *         description: Failed to apply configuration
 */
router.post('/apply',
  rateLimiters.critical,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    try {
      const opnsenseService = new OpnsenseService();
      const result = await opnsenseService.applyChanges();
      
      await auditLog(req, AUDITED_ACTIONS.CONFIG_CHANGE, 'critical', {
        action: 'apply_firewall_config',
        result: result
      });
      
      logger.info('Firewall configuration applied', {
        user_id: req.user.id,
        timestamp: new Date().toISOString()
      });
      
      res.json({
        success: true,
        message: 'Firewall configuration applied successfully',
        data: result
      });
    } catch (error) {
      logger.error('Failed to apply firewall configuration', {
        error: error.message,
        user_id: req.user.id
      });
      
      await auditLog(req, AUDITED_ACTIONS.CONFIG_CHANGE, 'critical', {
        action: 'apply_firewall_config_failed',
        error: error.message
      });
      
      throw error;
    }
  })
);

/**
 * @swagger
 * /api/v1/firewall/interfaces:
 *   get:
 *     summary: Get available network interfaces
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Interfaces retrieved successfully
 */
router.get('/interfaces',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const opnsenseService = new OpnsenseService();
    const interfaces = await opnsenseService.getInterfaces();
    
    res.json({
      success: true,
      message: 'Network interfaces retrieved successfully',
      data: interfaces
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/stats:
 *   get:
 *     summary: Get firewall statistics
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Statistics retrieved successfully
 */
router.get('/stats',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const ruleStats = await Rule.getStatistics();
    const totalRules = await Rule.count();
    const activeRules = await Rule.count({ where: { enabled: true, suspended: false } });
    const pendingSync = await Rule.count({ where: { sync_status: 'pending' } });
    const failedSync = await Rule.count({ where: { sync_status: 'failed' } });
    
    res.json({
      success: true,
      message: 'Firewall statistics retrieved successfully',
      data: {
        rules: {
          total: totalRules,
          active: activeRules,
          inactive: totalRules - activeRules,
          pending_sync: pendingSync,
          failed_sync: failedSync
        },
        by_interface: ruleStats.reduce((acc, stat) => {
          if (!acc[stat.interface]) acc[stat.interface] = {};
          acc[stat.interface][stat.action] = parseInt(stat.count);
          return acc;
        }, {}),
        sync_status: {
          pending: pendingSync,
          failed: failedSync,
          synced: totalRules - pendingSync - failedSync
        }
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/unused:
 *   get:
 *     summary: Find unused firewall rules
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Unused rules retrieved successfully
 */
router.get('/rules/unused',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const unusedRules = await Rule.findUnused();
    
    res.json({
      success: true,
      message: 'Unused firewall rules retrieved successfully',
      data: unusedRules,
      count: unusedRules.length
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/redundant:
 *   get:
 *     summary: Find redundant firewall rules
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Redundant rules retrieved successfully
 */
router.get('/rules/redundant',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const redundantRules = await Rule.findRedundant();
    
    res.json({
      success: true,
      message: 'Redundant firewall rules retrieved successfully',
      data: redundantRules,
      count: redundantRules.length
    });
  })
);

module.exports = router;