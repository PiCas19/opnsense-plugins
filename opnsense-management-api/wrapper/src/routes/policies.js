// src/routes/policies.js
const express = require('express');
const { authenticate, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { auditLog, AUDITED_ACTIONS } = require('../middleware/audit');
const { createRateLimiter } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError, ValidationError, ConflictError } = require('../middleware/errorHandler');

const PolicyService = require('../services/PolicyService');

const Policy = require('../models/Policy');
const Rule = require('../models/Rule');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

const { Op, fn, col, literal } = require('sequelize');
const logger = require('../utils/logger');

const router = express.Router();

// Limiter per le rotte policies
const policiesLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 200 : 5000,
});

// Apply rate limiting e autenticazione
router.use(policiesLimiter);
router.use(authenticate);

// Helper: include comuni per gli user relazionati
const userLiteAttrs = ['id', 'username', 'email'];
const includeUsers = [
  { model: User, as: 'createdBy', attributes: userLiteAttrs, required: false },
  { model: User, as: 'updatedBy', attributes: userLiteAttrs, required: false },
  { model: User, as: 'approver',  attributes: userLiteAttrs, required: false },
];

/**
 * @swagger
 * /api/v1/policies:
 *   get:
 *     summary: List firewall policies with pagination and filtering
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/',
  validators.searchQuery,
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, search, type, enabled, approval_status, created_by } = req.query;
    const service = new PolicyService(req.user);

    // Costruisci filtri per il service
    const filters = {};
    if (search) filters.name = search;
    if (type) filters.type = type;
    if (enabled !== undefined) filters.enabled = enabled === 'true';
    if (approval_status) filters.approval_status = approval_status;
    if (created_by) filters.created_by = Number(created_by);

    // Ottieni lista tramite service (usa cache e validazioni interne)
    const result = await service.getPolicies(filters, { page: parseInt(page, 10), limit: parseInt(limit, 10) });

    // Carica utenti (join) per le policy ritornate
    const ids = result.data.map(p => p.id);
    const joined = await Policy.findAll({
      where: { id: { [Op.in]: ids } },
      include: includeUsers,
      order: [
        ['priority', 'DESC'],
        ['created_at', 'DESC'],
      ]
    });

    const policiesWithStatus = joined.map((policy) => {
      const json = policy.toJSON();
      return {
        ...json,
        is_active: policy.isActive ? policy.isActive() : json.enabled,
        effectiveness_score: policy.getEffectivenessScore ? policy.getEffectivenessScore() : undefined,
        rules_count: Array.isArray(json.rules) ? json.rules.length : (json.rules_count ?? 0),
        created_by_user: json.createdBy || null,
        updated_by_user: json.updatedBy || null,
        approved_by_user: json.approver || null,
      };
    });

    await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
      action: 'list_policies',
      filters: { search, type, enabled, approval_status, created_by },
      count: policiesWithStatus.length,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: true,
      message: 'Policies retrieved successfully',
      data: policiesWithStatus,
      pagination: result.pagination,
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}:
 *   get:
 *     summary: Get specific policy by ID
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/:id',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const service = new PolicyService(req.user);

    // Dal service (cache + validazioni)
    const policy = await service.getPolicyById(Number(id));
    if (!policy) throw new NotFoundError('Policy not found');

    // Re-fetch con include User per risposte ricche
    const policyFull = await Policy.findByPk(id, { include: includeUsers });
    if (!policyFull) throw new NotFoundError('Policy not found');

    let associatedRules = [];
    if (policyFull.rules && policyFull.rules.length > 0) {
      associatedRules = await Rule.findAll({
        where: { id: { [Op.in]: policyFull.rules } },
        attributes: ['id', 'description', 'interface', 'action', 'enabled'],
      });
    }

    const json = policyFull.toJSON();
    const policyData = {
      ...json,
      associated_rules: associatedRules,
      effectiveness_score: policyFull.getEffectivenessScore?.(),
      is_active: policyFull.isActive?.(),
      next_activation: policyFull.getNextActivation?.(),
      created_by_user: json.createdBy || null,
      updated_by_user: json.updatedBy || null,
      approved_by_user: json.approver || null,
    };

    res.json({ success: true, message: 'Policy retrieved successfully', data: policyData });
  })
);

/**
 * @swagger
 * /api/v1/policies:
 *   post:
 *     summary: Create a new firewall policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/',
  validators.createPolicy,
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const service = new PolicyService(req.user);
    const policyData = { ...req.body };

    // Pre-validazioni
    const existingPolicy = await Policy.findOne({ where: { name: policyData.name } });
    if (existingPolicy) throw new ConflictError('Policy name already exists');

    if (policyData.rules?.length) {
      const existingRules = await Rule.findAll({
        where: { id: { [Op.in]: policyData.rules } },
        attributes: ['id'],
      });
      if (existingRules.length !== policyData.rules.length) {
        throw new ValidationError('Some referenced rules do not exist');
      }
    }

    const policy = await service.createPolicy(policyData);

    // Reload con users
    const createdFull = await Policy.findByPk(policy.id, { include: includeUsers });

    await auditLog(req, AUDITED_ACTIONS.POLICY_CREATE, 'info', {
      policy_id: policy.id,
      name: policy.name,
      type: policy.type,
      rules_count: policy.rules?.length || 0,
      user_id: req.user.id,
      username: req.user.username,
    });

    logger.info('Policy created successfully', {
      policy_id: policy.id,
      name: policy.name,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.status(201).json({
      success: true,
      message: 'Policy created successfully',
      data: {
        id: createdFull.id,
        name: createdFull.name,
        type: createdFull.type,
        approval_status: createdFull.approval_status,
        created_by_user: createdFull.createdBy || null,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}:
 *   put:
 *     summary: Update an existing policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.put(
  '/:id',
  validators.idParam,
  validators.updatePolicy,
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = { ...req.body };
    const service = new PolicyService(req.user);

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    if (updates.name && updates.name !== policy.name) {
      const existingPolicy = await Policy.findOne({ where: { name: updates.name, id: { [Op.ne]: id } } });
      if (existingPolicy) throw new ConflictError('Policy name already exists');
    }

    if (updates.rules?.length) {
      const existingRules = await Rule.findAll({ where: { id: { [Op.in]: updates.rules } }, attributes: ['id'] });
      if (existingRules.length !== updates.rules.length) {
        throw new ValidationError('Some referenced rules do not exist');
      }
    }

    const previousState = {
      name: policy.name,
      type: policy.type,
      enabled: policy.enabled,
      rules: policy.rules,
      priority: policy.priority,
    };

    const updated = await service.updatePolicy(Number(id), updates);
    const updatedFull = await Policy.findByPk(updated.id, { include: includeUsers });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      policy_id: updated.id,
      name: updated.name,
      changes: updates,
      previous_state: previousState,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: true,
      message: 'Policy updated successfully',
      data: {
        id: updatedFull.id,
        name: updatedFull.name,
        version: updatedFull.version,
        updated_by_user: updatedFull.updatedBy || null,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}/activate:
 *   post:
 *     summary: Activate a policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/:id/activate',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const service = new PolicyService(req.user);

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    if (policy.approval_status !== 'approved') {
      throw new ValidationError('Policy must be approved before activation');
    }

    const updated = await service.updatePolicy(Number(id), {
      enabled: true,
      last_activated_at: new Date(),
      activation_count: (policy.activation_count || 0) + 1,
    });

    const updatedFull = await Policy.findByPk(updated.id, { include: includeUsers });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      policy_id: updated.id,
      name: updated.name,
      action: 'activate',
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: true,
      message: 'Policy activated successfully',
      data: {
        id: updatedFull.id,
        name: updatedFull.name,
        enabled: true,
        activated_at: new Date().toISOString(),
        updated_by_user: updatedFull.updatedBy || null,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}/deactivate:
 *   post:
 *     summary: Deactivate a policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/:id/deactivate',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const service = new PolicyService(req.user);

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    const updated = await service.updatePolicy(Number(id), { enabled: false });
    const updatedFull = await Policy.findByPk(updated.id, { include: includeUsers });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      policy_id: updated.id,
      name: updated.name,
      action: 'deactivate',
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: true,
      message: 'Policy deactivated successfully',
      data: {
        id: updatedFull.id,
        name: updatedFull.name,
        enabled: false,
        deactivated_at: new Date().toISOString(),
        updated_by_user: updatedFull.updatedBy || null,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}/approve:
 *   post:
 *     summary: Approve a policy (admin only)
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/:id/approve',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { comments } = req.body;

    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Only administrators can approve policies',
        code: 'INSUFFICIENT_PERMISSIONS',
      });
    }

    const service = new PolicyService(req.user);
    const policy = await Policy.findByPk(id, { include: includeUsers });
    if (!policy) throw new NotFoundError('Policy not found');
    if (policy.approval_status === 'approved') throw new ValidationError('Policy is already approved');

    const updated = await service.updatePolicy(Number(id), {
      approval_status: 'approved',
      approved_by: req.user.id,
      approved_at: new Date(),
      review_comments: comments,
    });

    const updatedFull = await Policy.findByPk(updated.id, { include: includeUsers });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      policy_id: updated.id,
      name: updated.name,
      action: 'approve',
      comments,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: true,
      message: 'Policy approved successfully',
      data: {
        id: updatedFull.id,
        name: updatedFull.name,
        approval_status: updatedFull.approval_status,
        approved_at: updatedFull.approved_at,
        approved_by_user: updatedFull.approver || { id: req.user.id, username: req.user.username, email: req.user.email },
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}:
 *   delete:
 *     summary: Delete a policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.delete(
  '/:id',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_DELETE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const service = new PolicyService(req.user);

    const policy = await Policy.findByPk(id, { include: includeUsers });
    if (!policy) throw new NotFoundError('Policy not found');

    const policyInfo = {
      id: policy.id,
      name: policy.name,
      type: policy.type,
      rules_count: policy.rules?.length || 0,
      enabled: policy.enabled,
      created_by_user: policy.createdBy || null,
    };

    await service.deletePolicy(Number(id));

    await auditLog(req, AUDITED_ACTIONS.POLICY_DELETE, 'warning', {
      policy_id: policyInfo.id,
      name: policyInfo.name,
      type: policyInfo.type,
      rules_count: policyInfo.rules_count,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({ success: true, message: 'Policy deleted successfully' });
  })
);

/**
 * @swagger
 * /api/v1/policies/stats:
 *   get:
 *     summary: Get policy statistics
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/stats',
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    // Aggregati in un'unica query usando fn/col/literal
    const [aggRow] = await Policy.findAll({
      attributes: [
        [fn('COUNT', col('id')), 'total'],
        // enabled
        [literal('SUM(CASE WHEN "Policy"."enabled" = TRUE THEN 1 ELSE 0 END)'), 'enabled'],
        // approved
        [literal(`SUM(CASE WHEN "Policy"."approval_status" = 'approved' THEN 1 ELSE 0 END)`), 'approved'],
        // pending approval
        [literal(`SUM(CASE WHEN "Policy"."approval_status" = 'pending_approval' THEN 1 ELSE 0 END)`), 'pending_approval'],
      ],
      raw: true,
    });

    // Distribuzione per tipo
    const byTypeRows = await Policy.findAll({
      attributes: ['type', [fn('COUNT', col('id')), 'count']],
      group: ['type'],
      raw: true,
    });

    // Policies in scadenza (con include users)
    const expiringPolicies = await Policy.findExpiring(30, { include: includeUsers });

    const totals = {
      total: parseInt(aggRow.total, 10) || 0,
      active: parseInt(aggRow.enabled, 10) || 0,
      inactive: (parseInt(aggRow.total, 10) || 0) - (parseInt(aggRow.enabled, 10) || 0),
      approved: parseInt(aggRow.approved, 10) || 0,
      pending_approval: parseInt(aggRow.pending_approval, 10) || 0,
      expiring_soon: expiringPolicies.length,
    };

    const by_type = byTypeRows.reduce((acc, r) => {
      acc[r.type] = parseInt(r.count, 10) || 0;
      return acc;
    }, {});

    res.json({
      success: true,
      message: 'Policy statistics retrieved successfully',
      data: {
        totals,
        by_type,
        expiring_policies: expiringPolicies.map((p) => ({
          id: p.id,
          name: p.name,
          expires_at: p.expires_at,
          days_until_expiry: Math.ceil((new Date(p.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
          created_by_user: p.createdBy || null,
          approved_by_user: p.approver || null,
        })),
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/active:
 *   get:
 *     summary: Get currently active policies
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/active',
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const activePolicies = await Policy.findActive({ include: includeUsers });

    const policiesWithStatus = activePolicies.map((policy) => {
      const json = policy.toJSON();
      return {
        ...json,
        is_in_schedule: policy.isInSchedule?.(),
        effectiveness_score: policy.getEffectivenessScore?.(),
        next_activation: policy.getNextActivation?.(),
        created_by_user: json.createdBy || null,
        approved_by_user: json.approver || null,
      };
    });

    res.json({
      success: true,
      message: 'Active policies retrieved successfully',
      data: policiesWithStatus,
      count: policiesWithStatus.length,
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/expiring:
 *   get:
 *     summary: Get policies expiring soon
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/expiring',
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const { days = 30 } = req.query;

    const expiringPolicies = await Policy.findExpiring(parseInt(days, 10), { include: includeUsers });

    const policiesWithTimeLeft = expiringPolicies.map((policy) => {
      const json = policy.toJSON();
      return {
        ...json,
        days_until_expiry: Math.ceil((new Date(policy.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
        auto_renew: policy.auto_renew,
        created_by_user: json.createdBy || null,
      };
    });

    res.json({
      success: true,
      message: 'Expiring policies retrieved successfully',
      data: policiesWithTimeLeft,
      count: policiesWithTimeLeft.length,
      metadata: {
        days_ahead: parseInt(days, 10),
        auto_renewable: policiesWithTimeLeft.filter((p) => p.auto_renew).length,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}/export:
 *   get:
 *     summary: Export policy configuration
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/:id/export',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { format = 'json' } = req.query;
    const service = new PolicyService(req.user);

    const policy = await Policy.findByPk(id, { include: includeUsers });
    if (!policy) throw new NotFoundError('Policy not found');

    // Export via service
    const exportResult = await service.exportPolicies([Number(id)]);

    const exportData = {
      export_metadata: {
        ...exportResult.export_metadata,
        filtered: true,
      },
      policies: exportResult.policies.filter((p) => p.name === policy.name),
      created_by_user: policy.createdBy || null,
      approved_by_user: policy.approver || null,
    };

    if (format === 'yaml') {
      const yaml = require('yamljs');
      const yamlData = yaml.stringify(exportData, 2);
      res.set({
        'Content-Type': 'application/x-yaml',
        'Content-Disposition': `attachment; filename="policy-${policy.name}-${id}.yaml"`,
      });
      return res.send(yamlData);
    }

    res.set({
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="policy-${policy.name}-${id}.json"`,
    });

    res.json({
      success: true,
      message: 'Policy exported successfully',
      data: exportData,
      metadata: {
        exported_at: new Date().toISOString(),
        policy_version: policy.version,
        export_format: format,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}/clone:
 *   post:
 *     summary: Clone an existing policy
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/:id/clone',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { new_name, copy_rules = true, enabled = false } = req.body;
    const service = new PolicyService(req.user);

    if (!new_name) throw new ValidationError('new_name is required');

    const sourcePolicy = await Policy.findByPk(id, { include: includeUsers });
    if (!sourcePolicy) throw new NotFoundError('Source policy not found');

    const cloned = await service.clonePolicy(Number(id), {
      name: new_name,
      rules: copy_rules ? sourcePolicy.rules : [],
      enabled,
      description: `Cloned from: ${sourcePolicy.name}`,
      priority: sourcePolicy.priority,
      schedule: sourcePolicy.schedule,
      conditions: sourcePolicy.conditions,
      metadata: sourcePolicy.metadata,
    });

    const clonedFull = await Policy.findByPk(cloned.id, { include: includeUsers });

    await auditLog(req, AUDITED_ACTIONS.POLICY_CREATE, 'info', {
      action: 'clone_policy',
      source_policy_id: id,
      source_policy_name: sourcePolicy.name,
      new_policy_id: cloned.id,
      new_policy_name: new_name,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.status(201).json({
      success: true,
      message: 'Policy cloned successfully',
      data: {
        id: clonedFull.id,
        name: clonedFull.name,
        source_policy: { id: sourcePolicy.id, name: sourcePolicy.name },
        copied_rules: copy_rules ? (clonedFull.rules?.length || 0) : 0,
        created_by_user: clonedFull.createdBy || null,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/{id}/history:
 *   get:
 *     summary: Get policy change history
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/:id/history',
  validators.idParam,
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const policy = await Policy.findByPk(id, { include: includeUsers });
    if (!policy) throw new NotFoundError('Policy not found');

    const history = await AuditLog.findAll({
      where: { related_entity_type: 'policy', related_entity_id: id },
      order: [['timestamp', 'DESC']],
      limit: 50,
      attributes: ['audit_id', 'timestamp', 'action', 'username', 'changes', 'client_ip'],
    });

    res.json({
      success: true,
      message: 'Policy history retrieved successfully',
      data: {
        policy: {
          id: policy.id,
          name: policy.name,
          current_version: policy.version,
          created_by_user: policy.createdBy || null,
          approved_by_user: policy.approver || null,
        },
        history,
        count: history.length,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/check-expiry:
 *   post:
 *     summary: Check and auto-renew expiring policies
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/check-expiry',
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const renewedPolicies = await Policy.checkExpiring();

    await auditLog(req, AUDITED_ACTIONS.SYSTEM_ACCESS, 'info', {
      action: 'check_policy_expiry',
      renewed_count: renewedPolicies.filter((p) => p.auto_renew).length,
      expiring_count: renewedPolicies.length,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: true,
      message: 'Policy expiry check completed',
      data: {
        expiring_policies: renewedPolicies.length,
        auto_renewed: renewedPolicies.filter((p) => p.auto_renew).length,
        requires_attention: renewedPolicies.filter((p) => !p.auto_renew).length,
        policies: renewedPolicies.map((p) => ({
          id: p.id,
          name: p.name,
          expires_at: p.expires_at,
          auto_renewed: p.auto_renew,
        })),
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/validate:
 *   post:
 *     summary: Validate policy configuration
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/validate',
  authorize(PERMISSIONS.POLICY_READ),
  asyncHandler(async (req, res) => {
    const service = new PolicyService(req.user);
    const policyConfig = req.body;

    const errors = [];
    const warnings = [];
    const suggestions = [];

    if (policyConfig.name) {
      const existingPolicy = await Policy.findOne({ where: { name: policyConfig.name } });
      if (existingPolicy) errors.push('Policy name already exists');
    }

    if (policyConfig.rules?.length) {
      const existingRules = await Rule.findAll({
        where: { id: { [Op.in]: policyConfig.rules } },
        attributes: ['id', 'enabled'],
      });

      if (existingRules.length !== policyConfig.rules.length) {
        errors.push('Some referenced rules do not exist');
      }

      const disabledRules = existingRules.filter((rule) => !rule.enabled);
      if (disabledRules.length > 0) {
        warnings.push(`${disabledRules.length} referenced rules are currently disabled`);
      }
    }

    const typeValidation = await service.validatePolicyConfiguration({
      id: 0,
      type: policyConfig.type,
      description: policyConfig.description,
      priority: policyConfig.priority,
      configuration: policyConfig.configuration,
    });

    const isValid = errors.length === 0 && typeValidation.valid;

    res.json({
      success: isValid,
      message: isValid ? 'Policy configuration is valid' : 'Policy configuration has validation errors',
      data: {
        is_valid: isValid,
        errors: [...errors, ...typeValidation.errors],
        warnings: [...warnings, ...typeValidation.warnings],
        suggestions: [...suggestions, ...typeValidation.suggestions],
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/import:
 *   post:
 *     summary: Import policy configuration
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/import',
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { policy_data, overwrite = false, validate_only = false } = req.body;
    const service = new PolicyService(req.user);

    if (!policy_data) throw new ValidationError('policy_data is required');

    const errors = [];
    const warnings = [];

    if (!policy_data.name) errors.push('Policy name is required');
    if (!policy_data.type) errors.push('Policy type is required');
    if (!policy_data.rules || policy_data.rules.length === 0) errors.push('Policy must have at least one rule');

    let existingPolicy = null;
    if (policy_data.name) {
      existingPolicy = await Policy.findOne({ where: { name: policy_data.name } });
      if (existingPolicy && !overwrite) {
        errors.push('Policy name already exists. Use overwrite=true to replace it.');
      }
    }

    if (policy_data.rules?.length) {
      const existingRules = await Rule.findAll({
        where: { id: { [Op.in]: policy_data.rules } },
        attributes: ['id'],
      });
      if (existingRules.length !== policy_data.rules.length) {
        errors.push('Some referenced rules do not exist');
      }
    }

    const isValid = errors.length === 0;

    if (validate_only) {
      return res.json({
        success: isValid,
        message: isValid ? 'Policy import validation passed' : 'Policy import validation failed',
        data: { is_valid: isValid, errors, warnings },
      });
    }

    if (!isValid) {
      throw new ValidationError('Policy import validation failed', { errors, warnings });
    }

    const importResult = await service.importPolicies({ policies: [policy_data] }, { overwrite });

    await auditLog(req, AUDITED_ACTIONS.POLICY_CREATE, 'info', {
      action: 'import_policy',
      policy_name: policy_data.name,
      overwrite: overwrite && !!existingPolicy,
      user_id: req.user.id,
      username: req.user.username,
    });

    const imported = importResult.imported_policies?.[0];

    res.status(201).json({
      success: true,
      message: 'Policy imported successfully',
      data: {
        id: imported?.id,
        name: imported?.name,
        imported_at: new Date().toISOString(),
        overwritten: overwrite && !!existingPolicy,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/policies/bulk:
 *   patch:
 *     summary: Perform bulk operations on multiple policies
 *     tags: [Policies]
 *     security:
 *       - bearerAuth: []
 */
router.patch(
  '/bulk',
  authorize(PERMISSIONS.POLICY_WRITE),
  asyncHandler(async (req, res) => {
    const { policy_ids, operation, comments } = req.body;

    if (!policy_ids || policy_ids.length === 0) throw new ValidationError('policy_ids is required and cannot be empty');
    if (policy_ids.length > 50) throw new ValidationError('Cannot perform bulk operation on more than 50 policies');

    const validOperations = ['enable', 'disable', 'delete', 'approve', 'reject'];
    if (!validOperations.includes(operation)) {
      throw new ValidationError(`Invalid operation. Must be one of: ${validOperations.join(', ')}`);
    }

    if (['approve', 'reject'].includes(operation) && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Only administrators can approve or reject policies',
        code: 'INSUFFICIENT_PERMISSIONS',
      });
    }

    const service = new PolicyService(req.user);
    const results = { successful: 0, failed: 0, errors: [] };

    if (operation === 'enable' || operation === 'disable') {
      const updateData = { enabled: operation === 'enable' };
      const bulkResult = await service.bulkUpdatePolicies(policy_ids, updateData);
      results.successful = bulkResult.updated_count;
      results.failed = policy_ids.length - bulkResult.updated_count;
    } else {
      for (const id of policy_ids) {
        try {
          switch (operation) {
            case 'delete':
              await service.deletePolicy(Number(id));
              break;
            case 'approve':
              await service.updatePolicy(Number(id), {
                approval_status: 'approved',
                approved_by: req.user.id,
                approved_at: new Date(),
                review_comments: comments,
              });
              break;
            case 'reject':
              await service.updatePolicy(Number(id), {
                approval_status: 'rejected',
                reviewed_by: req.user.id,
                reviewed_at: new Date(),
                review_comments: comments,
              });
              break;
          }
          results.successful++;
        } catch (error) {
          results.failed++;
          const name = (await Policy.findByPk(id))?.name;
          results.errors.push({ policy_id: id, policy_name: name, error: error.message });
        }
      }
    }

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      bulk_operation: operation,
      policy_count: policy_ids.length,
      successful: results.successful,
      failed: results.failed,
      comments,
      user_id: req.user.id,
      username: req.user.username,
    });

    res.json({
      success: results.failed === 0,
      message: `Bulk ${operation} operation completed. ${results.successful} successful, ${results.failed} failed.`,
      data: results,
    });
  })
);

module.exports = router;