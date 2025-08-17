// src/routes/admin.js
const express = require('express');
const { Op } = require('sequelize');

// Middleware - Use simple version from errorHandler
const { validators } = require('../middleware/validation');
const { asyncHandler, NotFoundError } = require('../middleware/errorHandler');

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
 *     description: Administration endpoints for user and system management
 */

/**
 * @swagger
 * /api/v1/admin/users:
 *   get:
 *     summary: List all users with pagination and filters
 *     description: Retrieve a paginated list of users with optional search and role filtering
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
 *         description: Number of items per page
 *       - in: query
 *         name: q
 *         schema: { type: string }
 *         description: Search term for username or email
 *       - in: query
 *         name: role
 *         schema: { type: string, enum: [admin, operator, viewer] }
 *         description: Filter by user role
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean, example: true }
 *                 message: { type: string, example: "Users retrieved successfully" }
 *                 data: 
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id: { type: integer }
 *                       username: { type: string }
 *                       email: { type: string }
 *                       role: { type: string }
 *                       is_active: { type: boolean }
 *                       created_at: { type: string }
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     total: { type: integer }
 *                     page: { type: integer }
 *                     limit: { type: integer }
 *                     total_pages: { type: integer }
 *                     has_next: { type: boolean }
 *                     has_prev: { type: boolean }
 *       400:
 *         description: Invalid query parameters
 */
router.get(
  '/users',
  validators.searchQuery,
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, q: search, role } = req.query;

    const where = {};
    
    // Apply search filter for username or email
    if (search) {
      where[Op.or] = [
        { username: { [Op.iLike]: `%${search}%` } },
        { email: { [Op.iLike]: `%${search}%` } },
      ];
    }
    
    // Apply role filter
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
 *     description: Create a new user account with specified role and permissions
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, email, password, role]
 *             properties:
 *               username: 
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 30
 *                 pattern: "^[A-Za-z0-9]+$"
 *                 description: Alphanumeric username
 *                 example: "johndoe123"
 *               email: 
 *                 type: string
 *                 format: email
 *                 description: Valid email address
 *                 example: "john.doe@example.com"
 *               password: 
 *                 type: string
 *                 minLength: 8
 *                 description: Strong password with mixed case, numbers and symbols
 *                 example: "MyStr0ng!Pass"
 *               role: 
 *                 type: string
 *                 enum: [admin, operator, viewer]
 *                 description: User role determining access level
 *                 example: "operator"
 *               is_active: 
 *                 type: boolean
 *                 default: true
 *                 description: Whether the user account is active
 *                 example: true
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean, example: true }
 *                 message: { type: string, example: "User created successfully" }
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer }
 *                     username: { type: string }
 *                     email: { type: string }
 *                     role: { type: string }
 *                     is_active: { type: boolean }
 *                     created_at: { type: string }
 *       409:
 *         description: Username or email already exists
 *       400:
 *         description: Validation error
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

    // Create user (password is automatically hashed by the model hook)
    const user = await User.create({
      username,
      email,
      password,
      role,
      is_active,
    });

    // Log user creation for audit trail
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
 *     description: Retrieve detailed information about a specific user
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, minimum: 1 }
 *         description: User ID
 *         example: 123
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean, example: true }
 *                 message: { type: string, example: "User retrieved successfully" }
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer }
 *                     username: { type: string }
 *                     email: { type: string }
 *                     role: { type: string }
 *                     is_active: { type: boolean }
 *                     created_at: { type: string }
 *                     updated_at: { type: string }
 *       404:
 *         description: User not found
 *       400:
 *         description: Invalid user ID
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
 *     description: Update an existing user's information (excluding password)
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, minimum: 1 }
 *         description: User ID to update
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username: 
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 30
 *                 pattern: "^[A-Za-z0-9]+$"
 *                 description: New username (must be unique)
 *               email: 
 *                 type: string
 *                 format: email
 *                 description: New email address (must be unique)
 *               role: 
 *                 type: string
 *                 enum: [admin, operator, viewer]
 *                 description: User role
 *               is_active: 
 *                 type: boolean
 *                 description: Account status
 *             example:
 *               username: "newusername"
 *               email: "newemail@example.com"
 *               role: "operator"
 *               is_active: true
 *     responses:
 *       200:
 *         description: User updated successfully
 *       404:
 *         description: User not found
 *       409:
 *         description: Username or email conflict with existing user
 *       400:
 *         description: Validation error
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
        id: { [Op.ne]: id }, // Exclude current user from conflict check
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

    // Update user with provided data
    await user.update(updates);

    // Log update for audit trail
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
 *     summary: Delete user account
 *     description: Permanently delete a user account (soft delete if configured in model)
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, minimum: 1 }
 *         description: User ID to delete
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Cannot delete own account or validation error
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

    // Prevent self-deletion if authentication is implemented
    if (req.user && req.user.id === parseInt(id)) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete your own account',
        code: 'VALIDATION_ERROR',
      });
    }

    // Delete user (soft delete if paranoid: true in model)
    await user.destroy();

    // Log deletion for audit trail
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
 *     description: Retrieve system audit logs with optional filtering by level, action, user, and date range
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 50 }
 *         description: Items per page
 *       - in: query
 *         name: level
 *         schema: { type: string, enum: [info, warning, critical, security] }
 *         description: Filter by log level
 *       - in: query
 *         name: action
 *         schema: { type: string }
 *         description: Filter by action (partial match)
 *       - in: query
 *         name: user_id
 *         schema: { type: integer }
 *         description: Filter by user ID
 *       - in: query
 *         name: start_date
 *         schema: { type: string, format: date-time }
 *         description: Start date for filtering (ISO 8601)
 *         example: "2024-01-01T00:00:00Z"
 *       - in: query
 *         name: end_date
 *         schema: { type: string, format: date-time }
 *         description: End date for filtering (ISO 8601)
 *         example: "2024-12-31T23:59:59Z"
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *                 data: { type: array }
 *                 pagination: { type: object }
 *       400:
 *         description: Invalid query parameters
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

    // Apply level filter
    if (level) where.level = level;
    
    // Apply action filter (case-insensitive partial match)
    if (action) where.action = { [Op.iLike]: `%${action}%` };
    
    // Apply user filter
    if (user_id) where.user_id = user_id;

    // Apply date range filter
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
          as: 'user', // Ensure this association is defined in the AuditLog model
          attributes: ['id', 'username'],
          required: false, // LEFT JOIN to include logs without associated users
        },
      ],
      limit: limitNum,
      offset: (pageNum - 1) * limitNum,
      order: [['timestamp', 'DESC']], // Most recent logs first
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
 *     description: Retrieve comprehensive system information including hardware stats, database health, and application metrics
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
 *                 data:
 *                   type: object
 *                   properties:
 *                     system: { type: object }
 *                     database: { type: object }
 *                     application: { type: object }
 *                     timestamp: { type: string }
 *                     health_status: { type: string, enum: [healthy, degraded, error] }
 *       503:
 *         description: System health check failed
 */
router.get(
  '/system/info',
  asyncHandler(async (req, res) => {
    const os = require('os');
    const { sequelize } = require('../config/database');

    // Gather system information
    const system = {
      hostname: os.hostname(),
      platform: os.platform(),
      architecture: os.arch(),
      uptime: os.uptime(),
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem(),
        usage_percentage: Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 100),
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
          [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
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

    // Determine overall health status
    let healthStatus = 'healthy';
    if (!database.connected) {
      healthStatus = 'degraded';
    }
    if (system.memory.usage_percentage > 90) {
      healthStatus = 'degraded';
    }

    res.json({
      success: true,
      message: 'System information retrieved successfully',
      data: {
        system,
        database,
        application,
        timestamp: new Date().toISOString(),
        health_status: healthStatus,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/toggle-status:
 *   patch:
 *     summary: Toggle user active status
 *     description: Enable or disable a user account by toggling the is_active flag
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, minimum: 1 }
 *         description: User ID to toggle status
 *     responses:
 *       200:
 *         description: User status toggled successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *                 data:
 *                   type: object
 *                   properties:
 *                     id: { type: integer }
 *                     username: { type: string }
 *                     is_active: { type: boolean }
 *                     updated_at: { type: string }
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

    // Toggle the active status
    const newStatus = !user.is_active;
    await user.update({ is_active: newStatus });

    // Log status change for audit trail
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
 *     summary: Perform bulk actions on multiple users
 *     description: Execute batch operations on multiple users simultaneously (activate, deactivate, or delete)
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [user_ids, action]
 *             properties:
 *               user_ids: 
 *                 type: array
 *                 items: { type: integer }
 *                 minItems: 1
 *                 maxItems: 50
 *                 description: Array of user IDs to process
 *                 example: [1, 2, 3, 4, 5]
 *               action: 
 *                 type: string
 *                 enum: [activate, deactivate, delete]
 *                 description: Action to perform on selected users
 *                 example: "deactivate"
 *           example:
 *             user_ids: [1, 2, 3]
 *             action: "deactivate"
 *     responses:
 *       200:
 *         description: Bulk action completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *                 data:
 *                   type: object
 *                   properties:
 *                     action: { type: string }
 *                     affected_count: { type: integer }
 *                     processed_users: { type: integer }
 *       400:
 *         description: Invalid request or validation error
 *       404:
 *         description: No users found with provided IDs
 */
router.post(
  '/users/bulk-action',
  asyncHandler(async (req, res) => {
    const { user_ids, action } = req.body;

    // Validate input parameters
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

    // Prevent self-action if authentication is implemented
    if (req.user && user_ids.includes(req.user.id)) {
      return res.status(400).json({
        success: false,
        error: 'Cannot perform bulk action on your own account',
        code: 'VALIDATION_ERROR',
      });
    }

    // Find existing users
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

    // Execute bulk action
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

    // Log bulk action for audit trail
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

module.exports = router;