const express = require('express');
const { authenticate, requireRole, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { auditLog, AUDITED_ACTIONS } = require('../middleware/audit');
const { rateLimiters } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError } = require('../middleware/errorHandler');
const User = require('../models/User');
const ApiKey = require('../models/ApiKey');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

const router = express.Router();

// Apply admin rate limiting and authentication
router.use(rateLimiters.admin);
router.use(authenticate);
router.use(requireRole('admin'));

/**
 * @swagger
 * /api/v1/admin/users:
 *   get:
 *     summary: List all users
 *     tags: [Admin]
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
 *         name: role
 *         schema:
 *           type: string
 *           enum: [admin, operator, viewer, api_user]
 *     responses:
 *       200:
 *         description: List of users retrieved successfully
 *       403:
 *         description: Insufficient permissions
 */
router.get('/users', 
  validators.searchQuery,
  authorize(PERMISSIONS.USER_MANAGE),
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, search, role } = req.query;
    
    const whereClause = {};
    if (search) {
      whereClause[Op.or] = [
        { username: { [Op.iLike]: `%${search}%` } },
        { email: { [Op.iLike]: `%${search}%` } }
      ];
    }
    if (role) {
      whereClause.role = role;
    }
    
    const { count, rows } = await User.findAndCountAll({
      where: whereClause,
      attributes: ['id', 'username', 'email', 'role', 'is_active', 'created_at', 'last_login_at'],
      limit: parseInt(limit),
      offset: (parseInt(page) - 1) * parseInt(limit),
      order: [['created_at', 'DESC']],
    });
    
    await auditLog(req, AUDITED_ACTIONS.ADMIN_ACTION, 'info', {
      action: 'list_users',
      filters: { search, role }
    });
    
    res.json({
      success: true,
      message: 'Users retrieved successfully',
      data: rows,
      pagination: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        total_pages: Math.ceil(count / limit)
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users:
 *   post:
 *     summary: Create a new user
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *               - role
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 30
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *               role:
 *                 type: string
 *                 enum: [admin, operator, viewer, api_user]
 *               is_active:
 *                 type: boolean
 *                 default: true
 *     responses:
 *       201:
 *         description: User created successfully
 *       400:
 *         description: Validation error
 *       409:
 *         description: Username or email already exists
 */
router.post('/users',
  validators.createUser,
  authorize(PERMISSIONS.USER_MANAGE),
  asyncHandler(async (req, res) => {
    const { username, email, password, role, is_active = true } = req.body;
    
    // Hash password
    const { hashPassword } = require('../middleware/auth');
    const hashedPassword = await hashPassword(password);
    
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      role,
      is_active,
      created_by: req.user.id
    });
    
    await auditLog(req, AUDITED_ACTIONS.ADMIN_ACTION, 'info', {
      action: 'create_user',
      target_user: username,
      role: role
    });
    
    logger.info('User created successfully', {
      user_id: user.id,
      username: username,
      created_by: req.user.id
    });
    
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_active: user.is_active
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   put:
 *     summary: Update user details
 *     tags: [Admin]
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
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               role:
 *                 type: string
 *                 enum: [admin, operator, viewer, api_user]
 *               is_active:
 *                 type: boolean
 */
router.put('/users/:id',
  validators.idParam,
  validators.updateUser,
  authorize(PERMISSIONS.USER_MANAGE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    const user = await User.findByPk(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    // Store previous state for audit
    const previousState = {
      username: user.username,
      email: user.email,
      role: user.role,
      is_active: user.is_active
    };
    
    await user.update({
      ...updates,
      updated_by: req.user.id
    });
    
    await auditLog(req, AUDITED_ACTIONS.ADMIN_ACTION, 'info', {
      action: 'update_user',
      target_user: user.username,
      changes: updates,
      previous_state: previousState
    });
    
    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_active: user.is_active
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   delete:
 *     summary: Delete user (soft delete)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 */
router.delete('/users/:id',
  validators.idParam,
  authorize(PERMISSIONS.USER_MANAGE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete your own account',
        code: 'SELF_DELETE_FORBIDDEN'
      });
    }
    
    const user = await User.findByPk(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    await user.destroy();
    
    await auditLog(req, AUDITED_ACTIONS.ADMIN_ACTION, 'warning', {
      action: 'delete_user',
      target_user: user.username,
      target_role: user.role
    });
    
    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/api-keys:
 *   get:
 *     summary: List all API keys
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 */
router.get('/api-keys',
  authorize(PERMISSIONS.CONFIG_MANAGE),
  asyncHandler(async (req, res) => {
    const apiKeys = await ApiKey.findAll({
      include: [{
        model: User,
        attributes: ['username', 'email']
      }],
      attributes: ['id', 'name', 'description', 'created_at', 'last_used_at', 'expires_at', 'is_active'],
      order: [['created_at', 'DESC']]
    });
    
    res.json({
      success: true,
      message: 'API keys retrieved successfully',
      data: apiKeys
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/api-keys:
 *   post:
 *     summary: Create new API key
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - permissions
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               expires_at:
 *                 type: string
 *                 format: date-time
 *               permissions:
 *                 type: array
 *                 items:
 *                   type: string
 */
router.post('/api-keys',
  validators.createApiKey,
  authorize(PERMISSIONS.CONFIG_MANAGE),
  asyncHandler(async (req, res) => {
    const { name, description, expires_at, permissions, ip_restrictions } = req.body;
    
    // Generate secure API key
    const crypto = require('crypto');
    const apiKey = crypto.randomBytes(32).toString('hex');
    
    const createdApiKey = await ApiKey.create({
      name,
      description,
      key: apiKey,
      expires_at,
      permissions,
      ip_restrictions,
      user_id: req.user.id,
      created_by: req.user.id
    });
    
    await auditLog(req, AUDITED_ACTIONS.ADMIN_ACTION, 'info', {
      action: 'create_api_key',
      api_key_name: name,
      permissions: permissions
    });
    
    res.status(201).json({
      success: true,
      message: 'API key created successfully',
      data: {
        id: createdApiKey.id,
        name: createdApiKey.name,
        key: apiKey, // Only returned once
        expires_at: createdApiKey.expires_at
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/api-keys/{id}:
 *   delete:
 *     summary: Revoke API key
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 */
router.delete('/api-keys/:id',
  validators.idParam,
  authorize(PERMISSIONS.CONFIG_MANAGE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const apiKey = await ApiKey.findByPk(id);
    if (!apiKey) {
      throw new NotFoundError('API key not found');
    }
    
    await apiKey.update({ is_active: false });
    
    await auditLog(req, AUDITED_ACTIONS.ADMIN_ACTION, 'warning', {
      action: 'revoke_api_key',
      api_key_name: apiKey.name,
      api_key_id: apiKey.id
    });
    
    res.json({
      success: true,
      message: 'API key revoked successfully'
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/audit-logs:
 *   get:
 *     summary: Get audit logs
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *       - in: query
 *         name: level
 *         schema:
 *           type: string
 *           enum: [info, warning, critical, security]
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *       - in: query
 *         name: user_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: start_date
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: end_date
 *         schema:
 *           type: string
 *           format: date
 */
router.get('/audit-logs',
  validators.auditLogsQuery,
  authorize(PERMISSIONS.AUDIT_READ),
  asyncHandler(async (req, res) => {
    const { 
      page = 1, 
      limit = 50, 
      level, 
      action, 
      user_id, 
      start_date, 
      end_date 
    } = req.query;
    
    const whereClause = {};
    
    if (level) whereClause.level = level;
    if (action) whereClause.action = { [Op.iLike]: `%${action}%` };
    if (user_id) whereClause.user_id = user_id;
    
    if (start_date || end_date) {
      whereClause.timestamp = {};
      if (start_date) whereClause.timestamp[Op.gte] = new Date(start_date);
      if (end_date) whereClause.timestamp[Op.lte] = new Date(end_date);
    }
    
    const { count, rows } = await AuditLog.findAndCountAll({
      where: whereClause,
      limit: parseInt(limit),
      offset: (parseInt(page) - 1) * parseInt(limit),
      order: [['timestamp', 'DESC']],
      attributes: [
        'audit_id',
        'timestamp',
        'level',
        'action',
        'username',
        'client_ip',
        'method',
        'url',
        'status_code',
        'response_time'
      ]
    });
    
    res.json({
      success: true,
      message: 'Audit logs retrieved successfully',
      data: rows,
      pagination: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        total_pages: Math.ceil(count / limit)
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/system/info:
 *   get:
 *     summary: Get system information
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 */
router.get('/system/info',
  authorize(PERMISSIONS.SYSTEM_READ),
  asyncHandler(async (req, res) => {
    const os = require('os');
    const { sequelize } = require('../config/database');
    
    // Get system info
    const systemInfo = {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      uptime: os.uptime(),
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem()
      },
      cpu: os.cpus().length,
      load_average: os.loadavg()
    };
    
    // Get database info
    let dbInfo = {};
    try {
      const [results] = await sequelize.query('SELECT version()');
      dbInfo.version = results[0].version;
      dbInfo.connected = true;
    } catch (error) {
      dbInfo.connected = false;
      dbInfo.error = error.message;
    }
    
    // Get application stats
    const userCount = await User.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const recentLogs = await AuditLog.count({
      where: {
        timestamp: {
          [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000)
        }
      }
    });
    
    res.json({
      success: true,
      message: 'System information retrieved successfully',
      data: {
        system: systemInfo,
        database: dbInfo,
        application: {
          version: process.env.npm_package_version || '1.0.0',
          node_version: process.version,
          user_count: userCount,
          active_users: activeUsers,
          recent_audit_logs: recentLogs
        },
        timestamp: new Date().toISOString()
      }
    });
  })
);

module.exports = router;