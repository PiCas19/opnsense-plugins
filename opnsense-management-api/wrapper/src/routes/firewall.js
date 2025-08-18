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
const Rule = require('../models/Rule');
const User = require('../models/User');
const Alert = require('../models/Alert');
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

// RIMOSSO: inizializzazione forzata associazioni
// L'app.js si occupa già dell'inizializzazione

// Debug associazioni (solo per vedere se funzionano)
console.log('Firewall route - Current associations:');
console.log('Rule associations:', Object.keys(Rule.associations || {}));
console.log('User associations:', Object.keys(User.associations || {}));
console.log('Alert associations:', Object.keys(Alert.associations || {}));

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

    console.log('GET /rules called - using direct query approach');
    
    // Costruisci filtri
    const { Op } = require('sequelize');
    const whereClause = {};
    
    if (interfaceFilter) whereClause.interface = interfaceFilter;
    if (action) whereClause.action = action;
    if (enabled !== undefined) whereClause.enabled = enabled === 'true';
    if (protocol) whereClause.protocol = protocol;
    
    if (search) {
      whereClause[Op.or] = [
        { description: { [Op.iLike]: `%${search}%` } },
        { uuid: { [Op.iLike]: `%${search}%` } },
      ];
    }

    const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    try {
      // Query DIRETTA
      const { count, rows } = await Rule.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit, 10),
        offset: offset,
        order: [['sequence', 'ASC'], ['created_at', 'DESC']],
        // Prova con le associazioni SE funzionano
        include: Rule.associations && Rule.associations.createdBy ? [
          {
            model: User,
            as: 'createdBy',
            attributes: ['id', 'username', 'email'],
            required: false,
          },
          {
            model: User,
            as: 'updatedBy',
            attributes: ['id', 'username', 'email'],
            required: false,
          },
        ] : [], // Se non ci sono associazioni, array vuoto
      });

      const pagination = {
        current_page: parseInt(page, 10),
        per_page: parseInt(limit, 10),
        total: count,
        total_pages: Math.ceil(count / parseInt(limit, 10)),
        has_next: parseInt(page, 10) < Math.ceil(count / parseInt(limit, 10)),
        has_prev: parseInt(page, 10) > 1,
      };

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
        if (r.enabled) summary.enabled_count++;
        else summary.disabled_count++;
      }

      await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
        action: 'list_firewall_rules',
        filters: { search, interface: interfaceFilter, action, enabled, protocol },
        count: rows.length,
      });

      console.log(`Rules retrieved successfully: ${rows.length} rules`);

      res.json({
        success: true,
        message: 'Firewall rules retrieved successfully',
        data: rows,
        pagination: pagination,
        summary: summary,
      });

    } catch (error) {
      console.error('Error in direct query:', error.message);
      
      // Fallback SENZA include se anche quello fallisce
      const { count, rows } = await Rule.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit, 10),
        offset: offset,
        order: [['sequence', 'ASC'], ['created_at', 'DESC']],
        // NESSUN INCLUDE
      });

      const pagination = {
        current_page: parseInt(page, 10),
        per_page: parseInt(limit, 10),
        total: count,
        total_pages: Math.ceil(count / parseInt(limit, 10)),
        has_next: parseInt(page, 10) < Math.ceil(count / parseInt(limit, 10)),
        has_prev: parseInt(page, 10) > 1,
      };

      console.log(`Fallback query successful: ${rows.length} rules (no associations)`);

      res.json({
        success: true,
        message: 'Firewall rules retrieved successfully (fallback mode)',
        data: rows,
        pagination: pagination,
        summary: { note: 'Summary not available in fallback mode' },
      });
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

    try {
      // Query diretta
      const rule = await Rule.findByPk(parseInt(id, 10), {
        include: Rule.associations && Rule.associations.createdBy ? [
          {
            model: User,
            as: 'createdBy',
            attributes: ['id', 'username', 'email'],
            required: false,
          },
          {
            model: User,
            as: 'updatedBy',
            attributes: ['id', 'username', 'email'],
            required: false,
          },
        ] : [],
      });

      if (!rule) throw new NotFoundError('Firewall rule not found');

      res.json({
        success: true,
        message: 'Firewall rule retrieved successfully',
        data: rule,
      });
    } catch (error) {
      // Fallback senza associazioni
      const rule = await Rule.findByPk(parseInt(id, 10));
      if (!rule) throw new NotFoundError('Firewall rule not found');

      res.json({
        success: true,
        message: 'Firewall rule retrieved successfully (no associations)',
        data: rule,
      });
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
      created_by: getUserId(req) || 1, // Default user ID se non c'è auth
      updated_by: getUserId(req) || 1,
      source_config: req.body.source_config || { type: 'any' },
      destination_config: req.body.destination_config || { type: 'any' },
    };

    // Crea regola direttamente
    const rule = await Rule.create(ruleData);

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
        interface: rule.interface,
        action: rule.action,
        enabled: rule.enabled,
        sequence: rule.sequence,
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
      updated_by: getUserId(req) || 1,
    };

    const rule = await Rule.findByPk(parseInt(id, 10));
    if (!rule) throw new NotFoundError('Firewall rule not found');

    await rule.update(updates);

    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      changes: updates,
    });

    res.json({
      success: true,
      message: 'Firewall rule updated successfully',
      data: {
        id: rule.id,
        description: rule.description,
        interface: rule.interface,
        action: rule.action,
        enabled: rule.enabled,
        sequence: rule.sequence,
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

    const rule = await Rule.findByPk(parseInt(id, 10));
    if (!rule) throw new NotFoundError('Firewall rule not found');

    const ruleInfo = {
      id: rule.id,
      description: rule.description,
      interface: rule.interface,
      action: rule.action,
    };

    await rule.destroy();

    await auditLog(req, AUDITED_ACTIONS.RULE_DELETE, 'warning', {
      rule_id: ruleInfo.id,
      description: ruleInfo.description,
      interface: ruleInfo.interface,
      action: ruleInfo.action,
    });

    res.json({ 
      success: true, 
      message: 'Firewall rule deleted successfully' 
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
  asyncHandler(async (req, res) => {
    const stats = await Rule.getStatistics();
    const totalRules = await Rule.count();
    const activeRules = await Rule.count({ where: { enabled: true, suspended: false } });

    res.json({
      success: true,
      message: 'Firewall statistics retrieved successfully',
      data: {
        total: totalRules,
        active: activeRules,
        inactive: totalRules - activeRules,
        detailed_stats: stats,
      },
    });
  })
);

module.exports = router;