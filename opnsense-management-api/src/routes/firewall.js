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
const { asyncHandler, NotFoundError } = require('../middleware/errorHandler');
const OpnsenseService = require('../services/OpnsenseService');
const RuleService = require('../services/RuleService');
const Rule = require('../models/Rule');
const logger = require('../utils/logger');

const router = express.Router();

// helpers
const getUserId = (req) => (req.user && req.user.id) ? req.user.id : null;

// rate limiters locali (sostituisce rateLimiters.firewall/critical)
const firewallLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 300 : 5000,
});
const criticalLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 10 : 100,
});

// Applica limiter e (eventuale) auth
router.use(firewallLimiter);
router.use(authenticate);

/**
 * @swagger
 * /api/v1/firewall/rules:
 *   get:
 *     summary: List firewall rules with pagination and filtering
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
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
    } = req.query;

    const ruleService = new RuleService(req.user);
    const filters = {
      search,
      interface: interfaceFilter,
      action,
      enabled: enabled !== undefined ? enabled === 'true' : undefined,
      protocol,
    };

    const result = await ruleService.getRules(
      parseInt(page, 10),
      parseInt(limit, 10),
      filters
    );

    await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
      action: 'list_firewall_rules',
      filters,
      count: result.data.length,
    });

    res.json({
      success: true,
      message: 'Firewall rules retrieved successfully',
      data: result.data,
      pagination: result.pagination,
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
 */
router.get(
  '/rules/:id',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const rule = await Rule.findByPk(id, {
      include: [
        {
          model: require('../models/User'),
          as: 'creator',
          attributes: ['username'],
        },
      ],
    });

    if (!rule) throw new NotFoundError('Firewall rule not found');

    res.json({
      success: true,
      message: 'Firewall rule retrieved successfully',
      data: rule,
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
 */
router.post(
  '/rules',
  validators.createFirewallRule,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleData = {
      ...req.body,
      created_by: getUserId(req),
      sync_status: 'pending',
    };

    const ruleService = new RuleService(req.user);
    const rule = await ruleService.createRule(ruleData);

    // Sync con OPNsense
    try {
      const opnsenseService = new OpnsenseService();
      const opnsenseRuleId = await opnsenseService.createRule(rule);

      await rule.update({
        opnsense_uuid: opnsenseRuleId,
        sync_status: 'synced',
        last_synced_at: new Date(),
      });

      logger.info('Rule created and synced with OPNsense', {
        rule_id: rule.id,
        opnsense_uuid: opnsenseRuleId,
        user_id: getUserId(req),
      });
    } catch (syncError) {
      logger.error('Failed to sync rule with OPNsense', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: getUserId(req),
      });

      await rule.update({
        sync_status: 'failed',
        sync_error: syncError.message,
      });
    }

    await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      interface: rule.interface,
      action: rule.action,
    });

    res.status(201).json({
      success: true,
      message: 'Firewall rule created successfully',
      data: {
        id: rule.id,
        uuid: rule.uuid,
        description: rule.description,
        sync_status: rule.sync_status,
      },
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
 */
router.put(
  '/rules/:id',
  validators.idParam,
  validators.updateFirewallRule,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = {
      ...req.body,
      updated_by: getUserId(req),
    };

    const ruleService = new RuleService(req.user);
    const rule = await ruleService.updateRule(id, updates);

    try {
      const opnsenseService = new OpnsenseService();
      await opnsenseService.updateRule(rule.opnsense_uuid, rule);

      await rule.update({
        sync_status: 'synced',
        last_synced_at: new Date(),
        sync_error: null,
      });

      logger.info('Rule updated and synced with OPNsense', {
        rule_id: rule.id,
        user_id: getUserId(req),
      });
    } catch (syncError) {
      logger.error('Failed to sync updated rule with OPNsense', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: getUserId(req),
      });

      await rule.update({
        sync_status: 'failed',
        sync_error: syncError.message,
      });
    }

    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      changes: updates,
    });

    res.json({
      success: true,
      message: 'Firewall rule updated successfully',
      data: { id: rule.id, sync_status: rule.sync_status },
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
 */
router.patch(
  '/rules/:id/toggle',
  validators.idParam,
  validators.toggleFirewallRule,
  authorize(PERMISSIONS.FIREWALL_TOGGLE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { enabled, apply_immediately = false } = req.body;

    const rule = await Rule.findByPk(id);
    if (!rule) throw new NotFoundError('Firewall rule not found');

    const previousState = rule.enabled;

    await rule.update({
      enabled,
      updated_by: getUserId(req),
      sync_status: 'pending',
    });

    try {
      const opnsenseService = new OpnsenseService();
      await opnsenseService.toggleRule(rule.opnsense_uuid, enabled);
      if (apply_immediately) await opnsenseService.applyChanges();

      await rule.update({
        sync_status: 'synced',
        last_synced_at: new Date(),
        sync_error: null,
      });

      logger.info(`Rule ${enabled ? 'enabled' : 'disabled'}`, {
        rule_id: rule.id,
        description: rule.description,
        user_id: getUserId(req),
        applied: apply_immediately,
      });
    } catch (syncError) {
      logger.error('Failed to sync rule toggle with OPNsense', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: getUserId(req),
      });

      await rule.update({
        sync_status: 'failed',
        sync_error: syncError.message,
      });
    }

    await auditLog(req, AUDITED_ACTIONS.RULE_TOGGLE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      previous_state: previousState,
      new_state: enabled,
      applied_immediately: apply_immediately,
    });

    res.json({
      success: true,
      message: `Rule ${enabled ? 'enabled' : 'disabled'} successfully`,
      data: {
        id: rule.id,
        enabled: rule.enabled,
        sync_status: rule.sync_status,
        applied: apply_immediately,
      },
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
 */
router.delete(
  '/rules/:id',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_DELETE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const rule = await Rule.findByPk(id);
    if (!rule) throw new NotFoundError('Firewall rule not found');

    const ruleInfo = {
      id: rule.id,
      description: rule.description,
      interface: rule.interface,
      action: rule.action,
      opnsense_uuid: rule.opnsense_uuid,
    };

    try {
      if (rule.opnsense_uuid) {
        const opnsenseService = new OpnsenseService();
        await opnsenseService.deleteRule(rule.opnsense_uuid);

        logger.info('Rule deleted from OPNsense', {
          rule_id: rule.id,
          opnsense_uuid: rule.opnsense_uuid,
          user_id: getUserId(req),
        });
      }
    } catch (syncError) {
      logger.warn('Failed to delete rule from OPNsense, continuing with local deletion', {
        rule_id: rule.id,
        error: syncError.message,
        user_id: getUserId(req),
      });
    }

    await rule.destroy();

    await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', {
      rule_id: ruleInfo.id,
      description: ruleInfo.description,
      interface: ruleInfo.interface,
      action: ruleInfo.action,
    });

    res.json({ success: true, message: 'Firewall rule deleted successfully' });
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
 */
router.patch(
  '/rules/bulk',
  validators.bulkFirewallOperation,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { rule_ids, operation, apply_immediately = false } = req.body;

    const ruleService = new RuleService(req.user);
    const result = await ruleService.bulkOperation(
      rule_ids,
      operation,
      apply_immediately
    );

    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      bulk_operation: operation,
      rule_count: rule_ids.length,
      rule_ids,
      applied_immediately: apply_immediately,
    });

    res.json({
      success: true,
      message: `Bulk ${operation} operation completed successfully`,
      data: result,
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
 */
router.post(
  '/rules/sync',
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleService = new RuleService(req.user);
    const result = await ruleService.syncPendingRules();

    await auditLog(req, AUDITED_ACTIONS.SYSTEM_ACCESS, 'info', {
      action: 'sync_rules',
      synced_count: result.synced,
      failed_count: result.failed,
      total_pending: result.total,
    });

    res.json({
      success: true,
      message: 'Rule synchronization completed',
      data: result,
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
 */
router.post(
  '/apply',
  criticalLimiter,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const opnsenseService = new OpnsenseService();
    const result = await opnsenseService.applyChanges();

    await auditLog(req, AUDITED_ACTIONS.CONFIG_CHANGE, 'critical', {
      action: 'apply_firewall_config',
      result,
    });

    logger.info('Firewall configuration applied', {
      user_id: getUserId(req),
      timestamp: new Date().toISOString(),
    });

    res.json({
      success: true,
      message: 'Firewall configuration applied successfully',
      data: result,
    });
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
 */
router.get(
  '/interfaces',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (_req, res) => {
    const opnsenseService = new OpnsenseService();
    const interfaces = await opnsenseService.getInterfaces();

    res.json({
      success: true,
      message: 'Network interfaces retrieved successfully',
      data: interfaces,
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
 */
router.get(
  '/stats',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (_req, res) => {
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
          failed_sync: failedSync,
        },
        by_interface: ruleStats.reduce((acc, stat) => {
          if (!acc[stat.interface]) acc[stat.interface] = {};
          acc[stat.interface][stat.action] = parseInt(stat.count, 10);
          return acc;
        }, {}),
        sync_status: {
          pending: pendingSync,
          failed: failedSync,
          synced: totalRules - pendingSync - failedSync,
        },
      },
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
 */
router.get(
  '/rules/unused',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (_req, res) => {
    const unusedRules = await Rule.findUnused();

    res.json({
      success: true,
      message: 'Unused firewall rules retrieved successfully',
      data: unusedRules,
      count: unusedRules.length,
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
 */
router.get(
  '/rules/redundant',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (_req, res) => {
    const redundantRules = await Rule.findRedundant();

    res.json({
      success: true,
      message: 'Redundant firewall rules retrieved successfully',
      data: redundantRules,
      count: redundantRules.length,
    });
  })
);

module.exports = router;