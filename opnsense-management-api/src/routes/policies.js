// src/routes/policies.js
const express = require('express');
const { authenticate, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { auditLog, AUDITED_ACTIONS } = require('../middleware/audit');
// ⬇️ usa createRateLimiter invece di rateLimiters
const { createRateLimiter } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError, ValidationError, ConflictError } = require('../middleware/errorHandler');
const PolicyService = require('../services/PolicyService');
const Policy = require('../models/Policy');
const Rule = require('../models/Rule');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { Op } = require('sequelize');
const logger = require('../utils/logger');

const router = express.Router();

// Limiter per le rotte policies (sostituisce rateLimiters.firewall)
const policiesLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minuto
  max: process.env.NODE_ENV === 'production' ? 200 : 5000,
});

// Apply rate limiting e autenticazione
router.use(policiesLimiter);
router.use(authenticate);

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
    const { page = 1, limit = 20, search, type, enabled, approval_status } = req.query;

    const whereClause = {};

    if (search) {
      whereClause[Op.or] = [
        { name: { [Op.iLike]: `%${search}%` } },
        { description: { [Op.iLike]: `%${search}%` } },
      ];
    }
    if (type) whereClause.type = type;
    if (enabled !== undefined) whereClause.enabled = enabled === 'true';
    if (approval_status) whereClause.approval_status = approval_status;

    const { count, rows } = await Policy.findAndCountAll({
      where: whereClause,
      limit: parseInt(limit, 10),
      offset: (parseInt(page, 10) - 1) * parseInt(limit, 10),
      order: [
        ['priority', 'DESC'],
        ['created_at', 'DESC'],
      ],
      include: [
        {
          model: User,
          as: 'creator',
          attributes: ['username', 'email'],
        },
      ],
    });

    const policiesWithStatus = rows.map((policy) => ({
      ...policy.toJSON(),
      is_active: policy.isActive(),
      effectiveness_score: policy.getEffectivenessScore(),
      rules_count: policy.rules?.length || 0,
    }));

    await auditLog(req, AUDITED_ACTIONS.API_ACCESS, 'info', {
      action: 'list_policies',
      filters: { search, type, enabled, approval_status },
      count: rows.length,
    });

    res.json({
      success: true,
      message: 'Policies retrieved successfully',
      data: policiesWithStatus,
      pagination: {
        total: count,
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        total_pages: Math.ceil(count / parseInt(limit, 10)),
      },
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

    const policy = await Policy.findByPk(id, {
      include: [
        { model: User, as: 'creator', attributes: ['username', 'email'] },
        { model: User, as: 'approver', attributes: ['username', 'email'] },
      ],
    });

    if (!policy) throw new NotFoundError('Policy not found');

    let associatedRules = [];
    if (policy.rules && policy.rules.length > 0) {
      associatedRules = await Rule.findAll({
        where: { id: { [Op.in]: policy.rules } },
        attributes: ['id', 'description', 'interface', 'action', 'enabled'],
      });
    }

    const policyData = {
      ...policy.toJSON(),
      associated_rules: associatedRules,
      effectiveness_score: policy.getEffectivenessScore(),
      is_active: policy.isActive(),
      next_activation: policy.getNextActivation(),
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
    const policyData = { ...req.body, created_by: req.user.id, approval_status: 'draft' };

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

    const policy = await Policy.create(policyData);

    await auditLog(req, AUDITED_ACTIONS.POLICY_CREATE, 'info', {
      policy_id: policy.id,
      name: policy.name,
      type: policy.type,
      rules_count: policy.rules?.length || 0,
    });

    logger.info('Policy created successfully', { policy_id: policy.id, name: policy.name, user_id: req.user.id });

    res.status(201).json({
      success: true,
      message: 'Policy created successfully',
      data: { id: policy.id, name: policy.name, type: policy.type, approval_status: policy.approval_status },
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
    const updates = { ...req.body, updated_by: req.user.id };

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

    await policy.update(updates);

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      policy_id: policy.id,
      name: policy.name,
      changes: updates,
      previous_state: previousState,
    });

    res.json({ success: true, message: 'Policy updated successfully', data: { id: policy.id, name: policy.name, version: policy.version } });
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

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    if (policy.approval_status !== 'approved') {
      throw new ValidationError('Policy must be approved before activation');
    }

    await policy.update({
      enabled: true,
      last_activated_at: new Date(),
      activation_count: policy.activation_count + 1,
      updated_by: req.user.id,
    });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', { policy_id: policy.id, name: policy.name, action: 'activate' });

    res.json({
      success: true,
      message: 'Policy activated successfully',
      data: { id: policy.id, name: policy.name, enabled: true, activated_at: new Date().toISOString() },
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

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    await policy.update({ enabled: false, updated_by: req.user.id });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', { policy_id: policy.id, name: policy.name, action: 'deactivate' });

    res.json({
      success: true,
      message: 'Policy deactivated successfully',
      data: { id: policy.id, name: policy.name, enabled: false, deactivated_at: new Date().toISOString() },
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

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');
    if (policy.approval_status === 'approved') throw new ValidationError('Policy is already approved');

    await policy.update({
      approval_status: 'approved',
      approved_by: req.user.id,
      approved_at: new Date(),
      review_comments: comments,
    });

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      policy_id: policy.id,
      name: policy.name,
      action: 'approve',
      comments,
    });

    res.json({
      success: true,
      message: 'Policy approved successfully',
      data: { id: policy.id, name: policy.name, approval_status: policy.approval_status, approved_at: policy.approved_at },
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

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    const policyInfo = {
      id: policy.id,
      name: policy.name,
      type: policy.type,
      rules_count: policy.rules?.length || 0,
      enabled: policy.enabled,
    };

    await policy.destroy();

    await auditLog(req, AUDITED_ACTIONS.POLICY_DELETE, 'warning', {
      policy_id: policyInfo.id,
      name: policyInfo.name,
      type: policyInfo.type,
      rules_count: policyInfo.rules_count,
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
    const stats = await Policy.getStatistics();
    const totalPolicies = await Policy.count();
    const activePolicies = await Policy.count({ where: { enabled: true } });
    const approvedPolicies = await Policy.count({ where: { approval_status: 'approved' } });
    const pendingApproval = await Policy.count({ where: { approval_status: 'pending_approval' } });

    const expiringPolicies = await Policy.findExpiring(30);

    res.json({
      success: true,
      message: 'Policy statistics retrieved successfully',
      data: {
        totals: {
          total: totalPolicies,
          active: activePolicies,
          inactive: totalPolicies - activePolicies,
          approved: approvedPolicies,
          pending_approval: pendingApproval,
          expiring_soon: expiringPolicies.length,
        },
        by_type: stats,
        expiring_policies: expiringPolicies.map((p) => ({
          id: p.id,
          name: p.name,
          expires_at: p.expires_at,
          days_until_expiry: Math.ceil((new Date(p.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
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
    const activePolicies = await Policy.findActive();

    const policiesWithStatus = activePolicies.map((policy) => ({
      ...policy.toJSON(),
      is_in_schedule: policy.isInSchedule(),
      effectiveness_score: policy.getEffectivenessScore(),
      next_activation: policy.getNextActivation(),
    }));

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

    const expiringPolicies = await Policy.findExpiring(parseInt(days, 10));

    const policiesWithTimeLeft = expiringPolicies.map((policy) => ({
      ...policy.toJSON(),
      days_until_expiry: Math.ceil((new Date(policy.expires_at) - new Date()) / (1000 * 60 * 60 * 24)),
      auto_renew: policy.auto_renew,
    }));

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

    const policy = await Policy.findByPk(id);
    if (!policy) throw new NotFoundError('Policy not found');

    const exportData = policy.toExport();

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

    if (!new_name) throw new ValidationError('new_name is required');

    const sourcePolicy = await Policy.findByPk(id);
    if (!sourcePolicy) throw new NotFoundError('Source policy not found');

    const existingPolicy = await Policy.findOne({ where: { name: new_name } });
    if (existingPolicy) throw new ConflictError('Policy name already exists');

    const clonedPolicyData = {
      name: new_name,
      description: `Cloned from: ${sourcePolicy.name}`,
      type: sourcePolicy.type,
      rules: copy_rules ? [...sourcePolicy.rules] : [],
      enabled,
      priority: sourcePolicy.priority,
      schedule: sourcePolicy.schedule,
      conditions: sourcePolicy.conditions,
      metadata: sourcePolicy.metadata,
      created_by: req.user.id,
      approval_status: 'draft',
      parent_policy_id: sourcePolicy.id,
    };

    const clonedPolicy = await Policy.create(clonedPolicyData);

    await auditLog(req, AUDITED_ACTIONS.POLICY_CREATE, 'info', {
      action: 'clone_policy',
      source_policy_id: id,
      source_policy_name: sourcePolicy.name,
      new_policy_id: clonedPolicy.id,
      new_policy_name: new_name,
    });

    res.status(201).json({
      success: true,
      message: 'Policy cloned successfully',
      data: {
        id: clonedPolicy.id,
        name: clonedPolicy.name,
        source_policy: { id: sourcePolicy.id, name: sourcePolicy.name },
        copied_rules: copy_rules ? clonedPolicy.rules.length : 0,
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

    const policy = await Policy.findByPk(id);
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
        policy: { id: policy.id, name: policy.name, current_version: policy.version },
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

    if (policyConfig.schedule?.enabled) {
      if (policyConfig.schedule.start_time && policyConfig.schedule.end_time) {
        if (policyConfig.schedule.start_time >= policyConfig.schedule.end_time) {
          errors.push('Schedule start time must be before end time');
        }
      }
      if (!policyConfig.schedule.days || policyConfig.schedule.days.length === 0) {
        errors.push('Scheduled policies must specify at least one day');
      }
    }

    if (policyConfig.type === 'security' && (!policyConfig.priority || policyConfig.priority < 70)) {
      suggestions.push('Consider higher priority (70+) for security policies');
    }
    if (!policyConfig.description) {
      suggestions.push('Adding a description helps with policy management');
    }

    const isValid = errors.length === 0;

    res.json({
      success: isValid,
      message: isValid ? 'Policy configuration is valid' : 'Policy configuration has validation errors',
      data: { is_valid: isValid, errors, warnings, suggestions },
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

    let policy;
    if (existingPolicy && overwrite) {
      await existingPolicy.update({ ...policy_data, updated_by: req.user.id, version: existingPolicy.version + 1 });
      policy = existingPolicy;
    } else {
      policy = await Policy.create({ ...policy_data, created_by: req.user.id, approval_status: 'draft' });
    }

    await auditLog(req, AUDITED_ACTIONS.POLICY_CREATE, 'info', {
      action: 'import_policy',
      policy_name: policy.name,
      overwrite: overwrite && !!existingPolicy,
    });

    res.status(201).json({
      success: true,
      message: 'Policy imported successfully',
      data: {
        id: policy.id,
        name: policy.name,
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

    const policies = await Policy.findAll({ where: { id: { [Op.in]: policy_ids } } });
    if (policies.length !== policy_ids.length) throw new NotFoundError('Some policies were not found');

    const results = { successful: 0, failed: 0, errors: [] };

    for (const policy of policies) {
      try {
        switch (operation) {
          case 'enable':
            await policy.update({ enabled: true, updated_by: req.user.id });
            break;
          case 'disable':
            await policy.update({ enabled: false, updated_by: req.user.id });
            break;
          case 'delete':
            await policy.destroy();
            break;
          case 'approve':
            await policy.update({
              approval_status: 'approved',
              approved_by: req.user.id,
              approved_at: new Date(),
              review_comments: comments,
            });
            break;
          case 'reject':
            await policy.update({
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
        results.errors.push({ policy_id: policy.id, policy_name: policy.name, error: error.message });
      }
    }

    await auditLog(req, AUDITED_ACTIONS.POLICY_UPDATE, 'info', {
      bulk_operation: operation,
      policy_count: policy_ids.length,
      successful: results.successful,
      failed: results.failed,
      comments,
    });

    res.json({
      success: results.failed === 0,
      message: `Bulk ${operation} operation completed. ${results.successful} successful, ${results.failed} failed.`,
      data: results,
    });
  })
);

module.exports = router;