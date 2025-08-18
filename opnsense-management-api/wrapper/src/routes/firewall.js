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
const RulesService = require('../services/RuleService');
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

// Forza l'inizializzazione delle associazioni se non sono presenti
if (Object.keys(Rule.associations || {}).length === 0) {
  console.log('Associations not found, forcing initialization...');
  const models = { User, Rule, Alert };
  
  try {
    if (User.associate) {
      User.associate(models);
      console.log('User associations initialized');
    }
    if (Rule.associate) {
      Rule.associate(models);
      console.log('Rule associations initialized');
    }
    if (Alert.associate) {
      Alert.associate(models);
      console.log('Alert associations initialized');
    }
    
    console.log('All associations forced successfully');
  } catch (error) {
    console.error('Error forcing associations:', error.message);
  }
}

// Debug associazioni
console.log('Current associations:');
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
      // Query DIRETTA senza service per evitare problemi
      const { count, rows } = await Rule.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit, 10),
        offset: offset,
        order: [['sequence', 'ASC'], ['created_at', 'DESC']],
        // Prova con le associazioni SE funzionano
        include: Rule.associations.createdBy ? [
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

    // Query diretta invece del service
    const rule = await Rule.findByPk(parseInt(id, 10), {
      include: Rule.associations.createdBy ? [
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
      ] : [], // Fallback senza include
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
      sync_to_opnsense: req.body.sync_to_opnsense || false,
    };

    const rulesService = new RulesService(req.user);
    const rule = await rulesService.createRule(ruleData);

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
        opnsense_rule_id: rule.opnsense_rule_id,
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
      sync_to_opnsense: req.body.sync_to_opnsense || false,
    };

    const rulesService = new RulesService(req.user);
    const rule = await rulesService.updateRule(parseInt(id, 10), updates);

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
        opnsense_rule_id: rule.opnsense_rule_id,
      },
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
    const { enabled } = req.body;

    const rulesService = new RulesService(req.user);
    
    // Usa il service per l'update invece di query diretta
    const rule = await rulesService.updateRule(parseInt(id, 10), { 
      enabled,
      sync_to_opnsense: true // Forza sync quando toggli
    });

    await auditLog(req, AUDITED_ACTIONS.RULE_TOGGLE, 'info', {
      rule_id: rule.id,
      description: rule.description,
      new_state: enabled,
    });

    res.json({
      success: true,
      message: `Rule ${enabled ? 'enabled' : 'disabled'} successfully`,
      data: {
        id: rule.id,
        enabled: rule.enabled,
        description: rule.description,
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

    const rulesService = new RulesService(req.user);
    
    // Prima ottieni le info per l'audit log
    const rule = await rulesService.getRuleById(parseInt(id, 10));
    const ruleInfo = {
      id: rule.id,
      description: rule.description,
      interface: rule.interface,
      action: rule.action,
    };

    // Poi elimina
    await rulesService.deleteRule(parseInt(id, 10));

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
    const { rule_ids, operation } = req.body;

    const rulesService = new RulesService(req.user);
    
    // Mappa le operazioni ai metodi del service
    let result;
    
    if (operation === 'enable' || operation === 'disable') {
      result = await rulesService.bulkUpdateRules(rule_ids, { 
        enabled: operation === 'enable' 
      });
    } else if (operation === 'delete') {
      // Per il bulk delete, elimina uno per uno
      const deleteResults = [];
      for (const ruleId of rule_ids) {
        try {
          await rulesService.deleteRule(ruleId);
          deleteResults.push({ id: ruleId, success: true });
        } catch (error) {
          deleteResults.push({ id: ruleId, success: false, error: error.message });
        }
      }
      result = {
        success: deleteResults.every(r => r.success),
        results: deleteResults,
        updated_count: deleteResults.filter(r => r.success).length,
      };
    } else {
      throw new Error(`Unsupported bulk operation: ${operation}`);
    }

    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      bulk_operation: operation,
      rule_count: rule_ids.length,
      rule_ids,
      success_count: result.updated_count,
    });

    res.json({
      success: result.success,
      message: `Bulk ${operation} operation completed`,
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
    const rulesService = new RulesService(req.user);
    const result = await rulesService.syncRulesWithOpnsense();

    await auditLog(req, AUDITED_ACTIONS.SYSTEM_ACCESS, 'info', {
      action: 'sync_rules',
      synced_count: result.synced_count,
      failed_count: result.error_count,
      total_rules: result.total_rules,
    });

    res.json({
      success: result.success,
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
  asyncHandler(async (req, res) => {
    const rulesService = new RulesService(req.user);
    const stats = await rulesService.getRuleStatistics();

    res.json({
      success: true,
      message: 'Firewall statistics retrieved successfully',
      data: stats,
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

/**
 * @swagger
 * /api/v1/firewall/rules/{id}/clone:
 *   post:
 *     summary: Clone an existing firewall rule
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/rules/:id/clone',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const overrides = req.body || {};

    const rulesService = new RulesService(req.user);
    const clonedRule = await rulesService.cloneRule(parseInt(id, 10), overrides);

    await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
      action: 'clone_rule',
      original_rule_id: parseInt(id, 10),
      cloned_rule_id: clonedRule.id,
      description: clonedRule.description,
    });

    res.status(201).json({
      success: true,
      message: 'Firewall rule cloned successfully',
      data: clonedRule,
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/reorder:
 *   post:
 *     summary: Reorder rules within an interface
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/rules/reorder',
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const { interface: interfaceName, rule_order } = req.body;

    if (!interfaceName || !Array.isArray(rule_order)) {
      return res.status(400).json({
        success: false,
        message: 'Interface name and rule_order array are required',
      });
    }

    const rulesService = new RulesService(req.user);
    const result = await rulesService.reorderRules(interfaceName, rule_order);

    await auditLog(req, AUDITED_ACTIONS.RULE_UPDATE, 'info', {
      action: 'reorder_rules',
      interface: interfaceName,
      rule_count: rule_order.length,
    });

    res.json({
      success: result.success,
      message: 'Rules reordered successfully',
      data: result,
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/export:
 *   get:
 *     summary: Export firewall rules
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/rules/export',
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const { rule_ids } = req.query;
    const ruleIds = rule_ids ? rule_ids.split(',').map(id => parseInt(id, 10)) : null;

    const rulesService = new RulesService(req.user);
    const exportData = await rulesService.exportRules(ruleIds);

    await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
      action: 'export_rules',
      rule_count: exportData.rules.length,
    });

    res.json({
      success: true,
      message: 'Rules exported successfully',
      data: exportData,
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/import:
 *   post:
 *     summary: Import firewall rules
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/rules/import',
  authorize(PERMISSIONS.FIREWALL_WRITE),
  asyncHandler(async (req, res) => {
    const importData = req.body;
    const options = {
      overwrite: req.body.overwrite || false,
    };

    const rulesService = new RulesService(req.user);
    const result = await rulesService.importRules(importData, options);

    await auditLog(req, AUDITED_ACTIONS.RULE_CREATE, 'info', {
      action: 'import_rules',
      imported_count: result.imported,
      skipped_count: result.skipped,
      error_count: result.errors.length,
    });

    res.json({
      success: result.imported > 0,
      message: 'Rules import completed',
      data: result,
    });
  })
);

/**
 * @swagger
 * /api/v1/firewall/rules/{id}/validate:
 *   get:
 *     summary: Validate rule configuration
 *     tags: [Firewall]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/rules/:id/validate',
  validators.idParam,
  authorize(PERMISSIONS.FIREWALL_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const rulesService = new RulesService(req.user);
    const rule = await rulesService.getRuleById(parseInt(id, 10));
    const validation = await rulesService.validateRuleConfiguration(rule);

    res.json({
      success: true,
      message: 'Rule validation completed',
      data: validation,
    });
  })
);

module.exports = router;