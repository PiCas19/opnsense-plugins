// src/routes/admin.js
const express = require('express');
const { Op } = require('sequelize');

// Middleware
const { validators } = require('../middleware/validation');
const { asyncHandler } = require('../middleware/asyncHandler');
const { NotFoundError } = require('../middleware/errorHandler');

// Models
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Utils
const logger = require('../utils/logger');

const router = express.Router();

/**
 * @swagger
 * tags:
 *   - name: Admin
 *     description: Administration endpoints
 */

/**
 * @swagger
 * /api/v1/admin/users:
 *   get:
 *     summary: List all users with pagination and filters
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
 *       - in: query
 *         name: q
 *         schema: { type: string }
 *         description: Search term for username or email
 *       - in: query
 *         name: role
 *         schema: { type: string, enum: [admin, operator, viewer] }
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *                 data: { type: array }
 *                 pagination: { type: object }
 */
router.get(
  '/users',
  validators.searchQuery,
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, q: search, role } = req.query;

    const where = {};
    
    // Search filter
    if (search) {
      where[Op.or] = [
        { username: { [Op.iLike]: `%${search}%` } },
        { email: { [Op.iLike]: `%${search}%` } },
      ];
    }
    
    // Role filter
    if (role) {
      where.role = role;
    }

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    const { count, rows } = await User.findAndCountAll({
      where,
      attributes: {
        exclude: [
          'password',
          'two_factor_secret',
          'backup_codes',
          'email_verification_token',
          'password_reset_token',
        ],
      },
      limit: limitNum,
      offset: (pageNum - 1) * limitNum,
      order: [['createdAt', 'DESC']],
    });

    res.json({
      success: true,
      message: 'Users retrieved successfully',
      data: rows,
      pagination: {
        total: count,
        page: pageNum,
        limit: limitNum,
        total_pages: Math.ceil(count / limitNum),
        has_next: pageNum < Math.ceil(count / limitNum),
        has_prev: pageNum > 1,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users:
 *   post:
 *     summary: Create a new user
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, email, password, role]
 *             properties:
 *               username: { type: string, minLength: 3, maxLength: 30 }
 *               email: { type: string, format: email }
 *               password: { type: string, minLength: 8 }
 *               role: { type: string, enum: [admin, operator, viewer] }
 *               is_active: { type: boolean, default: true }
 *     responses:
 *       201:
 *         description: User created successfully
 *       409:
 *         description: Username or email already exists
 */
router.post(
  '/users',
  validators.createUser,
  asyncHandler(async (req, res) => {
    const { username, email, password, role, is_active = true } = req.body;

    // Check if username or email already exists
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [{ username }, { email }],
      },
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'User already exists',
        code: 'CONFLICT_ERROR',
        details: {
          field: existingUser.username === username ? 'username' : 'email',
          message: `${existingUser.username === username ? 'Username' : 'Email'} already taken`,
        },
      });
    }

    // Create user (password is automatically hashed by the model)
    const user = await User.create({
      username,
      email,
      password,
      role,
      is_active,
    });

    logger.info('User created successfully', {
      user_id: user.id,
      username: user.username,
      role: user.role,
      created_by: req.user?.id || 'system',
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_active: user.is_active,
        created_at: user.createdAt,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   get:
 *     summary: Get user details by ID
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *         description: User ID
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *       404:
 *         description: User not found
 */
router.get(
  '/users/:id',
  validators.idParam,
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await User.findByPk(id, {
      attributes: {
        exclude: [
          'password',
          'two_factor_secret',
          'backup_codes',
          'email_verification_token',
          'password_reset_token',
        ],
      },
    });

    if (!user) {
      throw new NotFoundError('User not found');
    }

    res.json({
      success: true,
      message: 'User retrieved successfully',
      data: user,
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   put:
 *     summary: Update user details
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username: { type: string }
 *               email: { type: string, format: email }
 *               role: { type: string, enum: [admin, operator, viewer] }
 *               is_active: { type: boolean }
 *     responses:
 *       200:
 *         description: User updated successfully
 *       404:
 *         description: User not found
 *       409:
 *         description: Username or email conflict
 */
router.put(
  '/users/:id',
  validators.idParam,
  validators.updateUser,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Check for conflicts if updating username or email
    if (updates.username || updates.email) {
      const whereClause = {
        id: { [Op.ne]: id },
      };

      if (updates.username && updates.email) {
        whereClause[Op.or] = [
          { username: updates.username },
          { email: updates.email },
        ];
      } else if (updates.username) {
        whereClause.username = updates.username;
      } else if (updates.email) {
        whereClause.email = updates.email;
      }

      const conflictUser = await User.findOne({ where: whereClause });
      if (conflictUser) {
        return res.status(409).json({
          success: false,
          error: 'Conflict with existing user',
          code: 'CONFLICT_ERROR',
          details: {
            field: conflictUser.username === updates.username ? 'username' : 'email',
            message: `${conflictUser.username === updates.username ? 'Username' : 'Email'} already taken`,
          },
        });
      }
    }

    await user.update(updates);

    logger.info('User updated successfully', {
      user_id: user.id,
      updated_fields: Object.keys(updates),
      updated_by: req.user?.id || 'system',
    });

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_active: user.is_active,
        updated_at: user.updatedAt,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   delete:
 *     summary: Delete user (soft delete)
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Cannot delete own account
 *       404:
 *         description: User not found
 */
router.delete(
  '/users/:id',
  validators.idParam,
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await User.findByPk(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Prevent self-deletion if auth is implemented
    if (req.user && req.user.id === parseInt(id)) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete your own account',
        code: 'VALIDATION_ERROR',
      });
    }

    await user.destroy();

    logger.info('User deleted successfully', {
      user_id: user.id,
      username: user.username,
      deleted_by: req.user?.id || 'system',
    });

    res.json({
      success: true,
      message: 'User deleted successfully',
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/audit-logs:
 *   get:
 *     summary: Get audit logs with filters
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 50 }
 *       - in: query
 *         name: level
 *         schema: { type: string, enum: [info, warning, critical, security] }
 *       - in: query
 *         name: action
 *         schema: { type: string }
 *       - in: query
 *         name: user_id
 *         schema: { type: integer }
 *       - in: query
 *         name: start_date
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: end_date
 *         schema: { type: string, format: date-time }
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully
 */
router.get(
  '/audit-logs',
  validators.auditLogsQuery,
  asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 50,
      level,
      action,
      user_id,
      start_date,
      end_date,
    } = req.query;

    const where = {};

    // Apply filters
    if (level) where.level = level;
    if (action) where.action = { [Op.iLike]: `%${action}%` };
    if (user_id) where.user_id = user_id;

    // Date range filter
    if (start_date || end_date) {
      where.timestamp = {};
      if (start_date) where.timestamp[Op.gte] = new Date(start_date);
      if (end_date) where.timestamp[Op.lte] = new Date(end_date);
    }

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    const { count, rows } = await AuditLog.findAndCountAll({
      where,
      include: [
        {
          model: User,
          as: 'user', // Make sure this association is defined in the model
          attributes: ['id', 'username'],
          required: false,
        },
      ],
      limit: limitNum,
      offset: (pageNum - 1) * limitNum,
      order: [['timestamp', 'DESC']],
    });

    res.json({
      success: true,
      message: 'Audit logs retrieved successfully',
      data: rows,
      pagination: {
        total: count,
        page: pageNum,
        limit: limitNum,
        total_pages: Math.ceil(count / limitNum),
        has_next: pageNum < Math.ceil(count / limitNum),
        has_prev: pageNum > 1,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/system/info:
 *   get:
 *     summary: Get system information and health status
 *     tags: [Admin]
 *     responses:
 *       200:
 *         description: System information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *                 data: { type: object }
 */
router.get(
  '/system/info',
  asyncHandler(async (req, res) => {
    const os = require('os');
    const { sequelize } = require('../config/database');

    // System information
    const system = {
      hostname: os.hostname(),
      platform: os.platform(),
      architecture: os.arch(),
      uptime: os.uptime(),
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem(),
        usage_percentage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100,
      },
      cpu: {
        cores: os.cpus().length,
        model: os.cpus()[0]?.model || 'Unknown',
        load_average: os.loadavg(),
      },
    };

    // Database health check
    const database = {};
    try {
      await sequelize.authenticate();
      const [results] = await sequelize.query('SELECT version()');
      database.version = results?.[0]?.version;
      database.connected = true;
      database.status = 'healthy';
    } catch (error) {
      database.connected = false;
      database.status = 'error';
      database.error = error.message;
    }

    // Application statistics
    const userCount = await User.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const recentLogs = await AuditLog.count({
      where: { 
        timestamp: { 
          [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) 
        } 
      },
    });

    const application = {
      name: 'Firewall Management System',
      version: process.env.npm_package_version || '1.0.0',
      node_version: process.version,
      environment: process.env.NODE_ENV || 'development',
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      statistics: {
        total_users: userCount,
        active_users: activeUsers,
        inactive_users: userCount - activeUsers,
        recent_audit_logs_24h: recentLogs,
      },
    };

    res.json({
      success: true,
      message: 'System information retrieved successfully',
      data: {
        system,
        database,
        application,
        timestamp: new Date().toISOString(),
        health_status: database.connected ? 'healthy' : 'degraded',
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/toggle-status:
 *   patch:
 *     summary: Toggle user active status
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: User status toggled successfully
 *       404:
 *         description: User not found
 */
router.patch(
  '/users/:id/toggle-status',
  validators.idParam,
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await User.findByPk(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    const newStatus = !user.is_active;
    await user.update({ is_active: newStatus });

    logger.info('User status toggled', {
      user_id: user.id,
      username: user.username,
      new_status: newStatus,
      changed_by: req.user?.id || 'system',
    });

    res.json({
      success: true,
      message: `User ${newStatus ? 'activated' : 'deactivated'} successfully`,
      data: {
        id: user.id,
        username: user.username,
        is_active: user.is_active,
        updated_at: user.updatedAt,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/bulk-action:
 *   post:
 *     summary: Perform bulk actions on users
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [user_ids, action]
 *             properties:
 *               user_ids: { type: array, items: { type: integer } }
 *               action: { type: string, enum: [activate, deactivate, delete] }
 *     responses:
 *       200:
 *         description: Bulk action completed successfully
 */
router.post(
  '/users/bulk-action',
  asyncHandler(async (req, res) => {
    const { user_ids, action } = req.body;

    // Basic validation
    if (!Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'user_ids must be a non-empty array',
        code: 'VALIDATION_ERROR',
      });
    }

    if (!['activate', 'deactivate', 'delete'].includes(action)) {
      return res.status(400).json({
        success: false,
        error: 'action must be one of: activate, deactivate, delete',
        code: 'VALIDATION_ERROR',
      });
    }

    // Prevent self-action if auth is implemented
    if (req.user && user_ids.includes(req.user.id)) {
      return res.status(400).json({
        success: false,
        error: 'Cannot perform bulk action on your own account',
        code: 'VALIDATION_ERROR',
      });
    }

    const users = await User.findAll({
      where: { id: { [Op.in]: user_ids } },
      attributes: ['id', 'username', 'is_active'],
    });

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No users found with provided IDs',
        code: 'NOT_FOUND_ERROR',
      });
    }

    let result;
    switch (action) {
      case 'activate':
        result = await User.update(
          { is_active: true },
          { where: { id: { [Op.in]: user_ids } } }
        );
        break;
      case 'deactivate':
        result = await User.update(
          { is_active: false },
          { where: { id: { [Op.in]: user_ids } } }
        );
        break;
      case 'delete':
        result = await User.destroy({
          where: { id: { [Op.in]: user_ids } }
        });
        break;
    }

    logger.info('Bulk user action performed', {
      action,
      affected_users: users.map(u => ({ id: u.id, username: u.username })),
      performed_by: req.user?.id || 'system',
    });

    res.json({
      success: true,
      message: `Bulk ${action} completed successfully`,
      data: {
        action,
        affected_count: Array.isArray(result) ? result[0] : result,
        processed_users: users.length,
      },
    });
  })
);

module.exports = router