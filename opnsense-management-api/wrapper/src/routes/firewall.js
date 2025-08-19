const express = require('express');

// Auth opzionale
let authenticate = (req, _res, next) => next();
let authorize = () => (req, _res, next) => next();
let PERMISSIONS = {};
try {
  ({ authenticate, authorize, PERMISSIONS } = require('../middleware/auth'));
} catch (_) { /* no auth in dev */ }

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
 *     summary: List firewall rules (core) with pagination and filtering
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
      enabled, // "true"/"false" o undefined
      protocol, // ignorato nelle core rules ma accettato
    } = req.query;

    logger.info('GET /rules called - fetching from OPNsense config.xml', {
      page, limit, filters: req.query
    });

    // costruisci filtri SOLO se presenti
    const filters = {};
    if (interfaceFilter) filters.interface = interfaceFilter;
    if (action) filters.action = action;
    if (search) filters.search = search;
    if (enabled !== undefined) {
      filters.enabled = enabled === 'true' || enabled === '1';
    }

    const opnsenseService = new OpnsenseService(req.user);
    const result = await opnsenseService.getFirewallRules({
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
      ...filters,
    });

    const { rows, total } = result;

    // Summary semplice
    const summary = {
      by_interface: {},
      by_action: {},
      enabled_count: 0,
      disabled_count: 0,
    };
    for (const r of rows) {
      summary.by_interface[r.interface] = (summary.by_interface[r.interface] || 0) + 1;
      summary.by_action[r.action] = (summary.by_action[r.action] || 0) + 1;
      if (r.enabled) summary.enabled_count++; else summary.disabled_count++;
    }

    await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
      action: 'list_firewall_rules',
      filters: { search, interface: interfaceFilter, action, enabled, protocol },
      count: rows.length,
    });

    res.json({
      success: true,
      message: 'Firewall rules retrieved successfully',
      data: rows,
      pagination: {
        current_page: Number(page),
        per_page: Number(limit),
        total,
        total_pages: Math.ceil(total / Number(limit)),
        has_next: Number(page) * Number(limit) < total,
        has_prev: Number(page) > 1,
      },
      summary,
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   get:
 *     summary: Get specific firewall rule by UUID
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
    logger.info(`GET /rules/${id} called - fetching from config.xml`);

    const opnsenseService = new OpnsenseService(req.user);
    const rule = await opnsenseService.getFirewallRuleById(id);

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
 *     summary: Create a new firewall rule (Automation API)
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/rules',
  validators.createFirewallRule,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const ruleData = { ...req.body, created_by: getUserId(req) || 1 };
    logger.info('POST /rules called - creating rule in OPNsense API', { ruleData });

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
        id: newRule.uuid,
        uuid: newRule.uuid,
        description: newRule.description,
        interface: newRule.interface,
        action: newRule.action,
        enabled: newRule.enabled,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   put:
 *     summary: Update an existing firewall rule (Automation API)
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
    const updates = { ...req.body, updated_by: getUserId(req) || 1 };
    logger.info(`PUT /rules/${id} called - updating rule in OPNsense API`, { updates });

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
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}:
 *   delete:
 *     summary: Delete a firewall rule (Automation API)
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

    const opnsenseService = new OpnsenseService(req.user);
    const success = await opnsenseService.deleteFirewallRule(id);
    if (!success) throw new NotFoundError('Firewall rule not found');

    await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', { rule_id: id });

    res.json({ success: true, message: 'Firewall rule deleted successfully' });
  })
);

/**
 * @swagger
 * /api/v1/firewall/stats:
 *   get:
 *     summary: Get firewall statistics (core rules)
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/stats',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    logger.info('GET /stats called - fetching from config.xml');

    const opnsenseService = new OpnsenseService(req.user);
    const { rows } = await opnsenseService.getFirewallRules({});

    const totalRules = rows.length;
    const activeRules = rows.filter(r => r.enabled).length;
    const inactiveRules = totalRules - activeRules;

    res.json({
      success: true,
      message: 'Firewall statistics retrieved successfully',
      data: {
        total: totalRules,
        active: activeRules,
        inactive: inactiveRules,
        detailed_stats: rows,
      },
    });
  })
);

module.exports = router;