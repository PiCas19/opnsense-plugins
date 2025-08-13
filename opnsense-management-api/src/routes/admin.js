// src/routes/admin.js
const express = require('express');
const { Op } = require('sequelize');

// middleware locali: solo ciò che esiste davvero
const { validators } = require('../middleware/validation');
const { asyncHandler } = require('../middleware/asyncHandler');
const { NotFoundError } = require('../middleware/errorHandler');

// modelli
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// util
const logger = require('../utils/logger');

const router = express.Router();

/**
 * @swagger
 * tags:
 *   - name: Admin
 *     description: Administration endpoints (no auth)
 */

/**
 * @swagger
 * /api/v1/admin/users:
 *   get:
 *     summary: List all users
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, minimum: 1, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *       - in: query
 *         name: role
 *         schema: { type: string, enum: [admin, operator, viewer] }
 *     responses:
 *       200: { description: List of users retrieved successfully }
 */
router.get(
  '/users',
  validators?.searchQuery || ((req, _res, next) => next()),
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, search, role } = req.query;

    const where = {};
    if (search) {
      where[Op.or] = [
        { username: { [Op.iLike]: `%${search}%` } },
        { email: { [Op.iLike]: `%${search}%` } },
      ];
    }
    if (role) where.role = role;

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    const { count, rows } = await User.findAndCountAll({
      where,
      // Evita colonne non esistenti / mismatch: lascia che Sequelize mappi da solo
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
 *       201: { description: User created successfully }
 */
router.post(
  '/users',
  validators?.createUser || ((req, _res, next) => next()),
  asyncHandler(async (req, res) => {
    const { username, email, password, role, is_active = true } = req.body;

    // NIENTE hash manuale: ci pensa il hook beforeCreate del modello User (bcryptjs)
    const user = await User.create({
      username,
      email,
      password,
      role,
      is_active,
    });

    logger.info('User created successfully', { user_id: user.id, username: user.username });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: user.toSafeJSON ? user.toSafeJSON() : user, // nel caso la method esista
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
 */
router.put(
  '/users/:id',
  validators?.idParam || ((req, _res, next) => next()),
  validators?.updateUser || ((req, _res, next) => next()),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;

    const user = await User.findByPk(id);
    if (!user) throw new NotFoundError('User not found');

    await user.update(updates);

    res.json({
      success: true,
      message: 'User updated successfully',
      data: user.toSafeJSON ? user.toSafeJSON() : user,
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
 */
router.delete(
  '/users/:id',
  validators?.idParam || ((req, _res, next) => next()),
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await User.findByPk(id);
    if (!user) throw new NotFoundError('User not found');

    await user.destroy();

    res.json({ success: true, message: 'User deleted successfully' });
  })
);

/**
 * @swagger
 * /api/v1/admin/audit-logs:
 *   get:
 *     summary: Get audit logs
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
 *         schema: { type: string, format: date }
 *       - in: query
 *         name: end_date
 *         schema: { type: string, format: date }
 */
router.get(
  '/audit-logs',
  validators?.auditLogsQuery || ((req, _res, next) => next()),
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50, level, action, user_id, start_date, end_date } = req.query;

    const where = {};
    if (level) where.level = level;
    if (action) where.action = { [Op.iLike]: `%${action}%` };
    if (user_id) where.user_id = user_id;

    if (start_date || end_date) {
      where.timestamp = {};
      if (start_date) where.timestamp[Op.gte] = new Date(start_date);
      if (end_date) where.timestamp[Op.lte] = new Date(end_date);
    }

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    const { count, rows } = await AuditLog.findAndCountAll({
      where,
      limit: limitNum,
      offset: (pageNum - 1) * limitNum,
      order: [['timestamp', 'DESC']],
      // niente attributes rigidi: evitiamo mismatch con il modello reale
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
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/admin/system/info:
 *   get:
 *     summary: Get system information
 *     tags: [Admin]
 *     responses:
 *       200: { description: System information }
 */
router.get(
  '/system/info',
  asyncHandler(async (_req, res) => {
    const os = require('os');
    const { sequelize } = require('../config/database');

    const system = {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      uptime: os.uptime(),
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem(),
      },
      cpu: os.cpus().length,
      load_average: os.loadavg(),
    };

    const db = {};
    try {
      const [results] = await sequelize.query('SELECT version()');
      db.version = results?.[0]?.version;
      db.connected = true;
    } catch (error) {
      db.connected = false;
      db.error = error.message;
    }

    const userCount = await User.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const recentLogs = await AuditLog.count({
      where: { timestamp: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
    });

    res.json({
      success: true,
      message: 'System information retrieved successfully',
      data: {
        system,
        database: db,
        application: {
          version: process.env.npm_package_version || '1.0.0',
          node_version: process.version,
          user_count: userCount,
          active_users: activeUsers,
          recent_audit_logs: recentLogs,
        },
        timestamp: new Date().toISOString(),
      },
    });
  })
);

module.exports = router;