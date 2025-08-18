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

    logger.info('GET /rules called - fetching from OPNsense API', { page, limit, filters: req.query });

    const filters = {
      interface: interfaceFilter,
      action,
      enabled: enabled === 'true',
      protocol,
      search,
    };

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const rulesData = await opnsenseService.getFirewallRules({
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        ...filters,
      });

      const pagination = {
        current_page: parseInt(page, 10),
        per_page: parseInt(limit, 10),
        total: rulesData.length, // Adjust based on actual response structure from OpnsenseService
        total_pages: Math.ceil(rulesData.length / parseInt(limit, 10)),
        has_next: parseInt(page, 10) < Math.ceil(rulesData.length / parseInt(limit, 10)),
        has_prev: parseInt(page, 10) > 1,
      };

      // Summary semplice
      const summary = {
        by_interface: {},
        by_action: {},
        enabled_count: 0,
        disabled_count: 0,
      };

      for (const r of rulesData) {
        summary.by_interface[r.interface] = (summary.by_interface[r.interface] || 0) + 1;
        summary.by_action[r.action] = (summary.by_action[r.action] || 0) + 1;
        if (r.enabled) summary.enabled_count++;
        else summary.disabled_count++;
      }

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'list_firewall_rules',
        filters: { search, interface: interfaceFilter, action, enabled, protocol },
        count: rulesData.length,
      });

      logger.info(`Rules retrieved successfully from OPNsense: ${rulesData.length} rules`);

      res.json({
        success: true,
        message: 'Firewall rules retrieved successfully',
        data: rulesData,
        pagination: pagination,
        summary: summary,
      });
    } catch (error) {
      logger.error('Error fetching rules from OPNsense API:', { error: error.message, filters: req.query });
      throw new Error('Failed to retrieve firewall rules from OPNsense');
    }
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

    logger.info(`GET /rules/${id} called - fetching from OPNsense API`);

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const rule = await opnsenseService.getFirewallRules({ ruleId: id }); // Adjust based on actual method

      if (!rule || !rule.length) throw new NotFoundError('Firewall rule not found');

      res.json({
        success: true,
        message: 'Firewall rule retrieved successfully',
        data: rule[0], // Assuming getFirewallRules returns an array with the rule
      });
    } catch (error) {
      logger.error(`Error fetching rule ${id} from OPNsense API:`, { error: error.message });
      throw new NotFoundError('Firewall rule not found');
    }
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
      created_by: getUserId(req) || 1,
    };

    logger.info('POST /rules called - creating rule in OPNsense API', { ruleData });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const newRule = await opnsenseService.createFirewallRule(ruleData);

      await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
        rule_id: newRule.uuid,
        description: newRule.description,
        interface: newRule.interface,
        action: newRule.action,
      });

      res.status(201).json({
        success: true,
        message: 'Firewall rule created successfully',
        data: {
          id: newRule.uuid, // Using uuid as id from OPNsense
          uuid: newRule.uuid,
          description: newRule.description,
          interface: newRule.interface,
          action: newRule.action,
          enabled: newRule.enabled,
        },
      });
    } catch (error) {
      logger.error('Error creating rule in OPNsense API:', { error: error.message, ruleData });
      throw new Error('Failed to create firewall rule in OPNsense');
    }
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
      updated_by: getUserId(req) || 1,
    };

    logger.info(`PUT /rules/${id} called - updating rule in OPNsense API`, { updates });

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const updatedRule = await opnsenseService.updateFirewallRule(id, updates);

      await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
        rule_id: updatedRule.uuid,
        description: updatedRule.description,
        changes: updates,
      });

      res.json({
        success: true,
        message: 'Firewall rule updated successfully',
        data: {
          id: updatedRule.uuid,
          description: updatedRule.description,
          interface: updatedRule.interface,
          action: updatedRule.action,
          enabled: updatedRule.enabled,
        },
      });
    } catch (error) {
      logger.error(`Error updating rule ${id} in OPNsense API:`, { error: error.message, updates });
      throw new NotFoundError('Firewall rule not found or update failed');
    }
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

    logger.info(`DELETE /rules/${id} called - deleting rule from OPNsense API`);

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const success = await opnsenseService.deleteFirewallRule(id);

      if (!success) throw new NotFoundError('Firewall rule not found');

      await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', {
        rule_id: id,
      });

      res.json({
        success: true,
        message: 'Firewall rule deleted successfully',
      });
    } catch (error) {
      logger.error(`Error deleting rule ${id} from OPNsense API:`, { error: error.message });
      throw new NotFoundError('Firewall rule not found or deletion failed');
    }
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
  asyncHandler(async (req, res) => {
    logger.info('GET /stats called - fetching from OPNsense API');

    try {
      const opnsenseService = new OpnsenseService(req.user);
      const stats = await opnsenseService.getFirewallRules(); // Adjust if a specific stats method exists

      const totalRules = stats.length;
      const activeRules = stats.filter(r => r.enabled).length;
      const inactiveRules = totalRules - activeRules;

      res.json({
        success: true,
        message: 'Firewall statistics retrieved successfully',
        data: {
          total: totalRules,
          active: activeRules,
          inactive: inactiveRules,
          detailed_stats: stats,
        },
      });
    } catch (error) {
      logger.error('Error fetching firewall stats from OPNsense API:', { error: error.message });
      throw new Error('Failed to retrieve firewall statistics');
    }
  })
);

module.exports = router;