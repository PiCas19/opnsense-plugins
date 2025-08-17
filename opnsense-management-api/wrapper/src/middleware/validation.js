// src/middleware/validation.js
const { z } = require('zod');
const net = require('node:net');
const { param, validationResult } = require('express-validator');
const { ValidationError } = require('./errorHandler');
const logger = require('../utils/logger');

/* ----------------------- Helper functions & regex patterns ----------------------- */

// MAC address pattern (supports both : and - separators)
const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;

// CIDR notation pattern for IP networks
const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

/**
 * Validates CIDR notation for IPv4 networks
 * @param {string} value - CIDR string to validate
 * @returns {boolean} - True if valid CIDR notation
 */
const isCIDR = (value) => {
  if (!cidrRegex.test(value)) return false;
  
  const [ip, prefix] = value.split('/');
  const octets = ip.split('.').map(Number);
  
  // Validate IP octets (0-255)
  if (octets.length !== 4 || octets.some((o) => o < 0 || o > 255)) return false;
  
  // Validate prefix length (0-32)
  const p = Number(prefix);
  return Number.isInteger(p) && p >= 0 && p <= 32;
};

/**
 * Strong password pattern requiring:
 * - At least one lowercase letter
 * - At least one uppercase letter  
 * - At least one digit
 * - At least one special character (@$!%*?&)
 * - Only allows characters from the specified groups
 */
const strongPwd = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/;

/* ------------------------- Common validation schemas ------------------------- */

const commonSchemas = {
  // UUID v4 validation
  uuid: z.string().uuid(),
  
  // Positive integer ID (auto-coerced from string)
  id: z.coerce.number().int().positive(),
  
  // IPv4/IPv6 address validation using Node.js net module
  ipAddress: z.string().refine((v) => net.isIP(v) !== 0, 'Invalid IP address'),
  
  // Network port validation (1-65535)
  port: z.coerce.number().int().min(1).max(65535),
  
  // Network protocol enum
  protocol: z.enum(['tcp', 'udp', 'icmp', 'any']),
  
  // MAC address validation with regex
  macAddress: z.string().regex(macRegex, 'Invalid MAC address'),

  // Pagination parameters with defaults
  pagination: z
    .object({
      page: z.coerce.number().int().min(1).default(1),
      limit: z.coerce.number().int().min(1).max(100).default(20),
      sort: z.enum(['asc', 'desc']).default('desc'),
      order_by: z.string().default('created_at'),
    })
    .strip(),

  // Date range validation with custom logic
  dateRange: z
    .object({
      start_date: z.string().datetime().optional(),
      end_date: z.string().datetime().optional(),
    })
    .strip()
    .superRefine((val, ctx) => {
      // Ensure end_date is not before start_date
      if (val.start_date && val.end_date) {
        if (new Date(val.end_date) < new Date(val.start_date)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['end_date'],
            message: 'end_date must be >= start_date',
          });
        }
      }
    }),
};

/* ------------------------- Authentication schemas ------------------------- */

const authSchemas = {
  // User login validation
  login: z
    .object({
      username: z.string().min(3).max(30).regex(/^[A-Za-z0-9]+$/, 'Must be alphanumeric'),
      password: z.string().min(8).max(128),
      remember_me: z.boolean().default(false).optional(),
    })
    .strip(),

  // User registration with password confirmation
  register: z
    .object({
      username: z.string().min(3).max(30).regex(/^[A-Za-z0-9]+$/, 'Must be alphanumeric'),
      email: z.string().email(),
      password: z.string().min(8).max(128).regex(strongPwd, 'Weak password'),
      confirm_password: z.string().min(8).max(128),
      role: z.enum(['admin', 'operator', 'viewer']).default('viewer').optional(),
    })
    .strip()
    .superRefine((val, ctx) => {
      // Validate password confirmation matches
      if (val.password !== val.confirm_password) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['confirm_password'],
          message: 'Passwords do not match',
        });
      }
    }),

  // Password change with current password verification
  changePassword: z
    .object({
      current_password: z.string().min(1),
      new_password: z.string().min(8).max(128).regex(strongPwd, 'Weak password'),
      confirm_password: z.string().min(8).max(128),
    })
    .strip()
    .superRefine((val, ctx) => {
      // Validate new password confirmation
      if (val.new_password !== val.confirm_password) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['confirm_password'],
          message: 'Passwords do not match',
        });
      }
    }),

  // JWT refresh token validation
  refreshToken: z.object({ refresh_token: z.string().min(1) }).strip(),
};

/* ---------------------- Firewall rule schemas ---------------------- */

// Address type: any (wildcard)
const addressAny = z.object({ type: z.literal('any') }).strip();

// Address type: single IP with optional port
const addressSingle = z
  .object({
    type: z.literal('single'),
    address: commonSchemas.ipAddress,
    port: commonSchemas.port.optional(),
  })
  .strip();

// Address type: network CIDR with optional port
const addressNetwork = z
  .object({
    type: z.literal('network'),
    network: z.string().regex(cidrRegex, 'Invalid CIDR').refine(isCIDR, 'Invalid CIDR'),
    port: commonSchemas.port.optional(),
  })
  .strip();

// Address type: alias reference with optional port
const addressAlias = z
  .object({
    type: z.literal('alias'),
    address: z.string().min(1),
    port: commonSchemas.port.optional(),
  })
  .strip();

// Discriminated union for different address types
const endpointSchema = z.discriminatedUnion('type', [
  addressAny,
  addressSingle,
  addressNetwork,
  addressAlias,
]);

// Base firewall rule schema
const createRuleBase = z
  .object({
    description: z.string().max(255),
    interface: z.enum(['wan', 'lan', 'dmz', 'opt1', 'opt2']),
    direction: z.enum(['in', 'out']).default('in'),
    action: z.enum(['pass', 'block', 'reject']),
    protocol: commonSchemas.protocol,
    source: endpointSchema,
    destination: endpointSchema,
    enabled: z.boolean().default(true),
    log: z.boolean().default(false),
    sequence: z.coerce.number().int().min(1).max(9999).optional(),
  })
  .strip();

const firewallSchemas = {
  // Create new firewall rule
  createRule: createRuleBase,
  
  // Update existing rule (all fields optional)
  updateRule: createRuleBase.partial(),
  
  // Toggle rule enabled/disabled state
  toggleRule: z
    .object({
      enabled: z.boolean(),
      apply_immediately: z.boolean().default(false).optional(),
    })
    .strip(),
    
  // Bulk operations on multiple rules
  bulkOperation: z
    .object({
      rule_ids: z.array(commonSchemas.id).min(1).max(50),
      operation: z.enum(['enable', 'disable', 'delete']),
      apply_immediately: z.boolean().default(false).optional(),
    })
    .strip(),
};

/* ------------------------ Policy and admin schemas ------------------------ */

// Schedule configuration for time-based policies
const scheduleSchema = z
  .object({
    enabled: z.boolean().default(false).optional(),
    start_time: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).optional(),
    end_time: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).optional(),
    days: z
      .array(
        z.enum([
          'monday',
          'tuesday',
          'wednesday',
          'thursday',
          'friday',
          'saturday',
          'sunday',
        ])
      )
      .optional(),
  })
  .strip();

// Conditional matching criteria for policies
const conditionsSchema = z
  .object({
    source_ips: z.array(commonSchemas.ipAddress).optional(),
    destination_ips: z.array(commonSchemas.ipAddress).optional(),
    protocols: z.array(commonSchemas.protocol).optional(),
    ports: z.array(commonSchemas.port).optional(),
  })
  .strip();

// Base policy creation schema
const policyCreateBase = z
  .object({
    name: z.string().min(3).max(100),
    description: z.string().max(500).optional(),
    type: z.enum(['security', 'access', 'qos', 'custom']),
    rules: z.array(commonSchemas.id).min(1), // Must reference at least one rule
    enabled: z.boolean().default(true).optional(),
    priority: z.coerce.number().int().min(1).max(100).default(50).optional(),
    schedule: scheduleSchema.optional(),
    conditions: conditionsSchema.optional(),
  })
  .strip();

const policySchemas = {
  createPolicy: policyCreateBase,
  updatePolicy: policyCreateBase.partial(),
};

// Admin user creation schema
const adminCreateBase = z
  .object({
    username: z.string().min(3).max(30).regex(/^[A-Za-z0-9]+$/, 'Must be alphanumeric'),
    email: z.string().email(),
    password: z.string().min(8).max(128).regex(strongPwd, 'Weak password'),
    role: z.enum(['admin', 'operator', 'viewer']),
    is_active: z.boolean().default(true).optional(),
    permissions: z.array(z.string()).optional(),
  })
  .strip();

const adminSchemas = {
  createUser: adminCreateBase,
  // Update user schema excludes password (handled separately)
  updateUser: adminCreateBase.partial().omit({ password: true }),
  
  // API key creation schema
  createApiKey: z
    .object({
      name: z.string().min(3).max(100),
      description: z.string().max(500).optional(),
      expires_at: z.union([z.string().datetime(), z.coerce.date()]).optional(),
      permissions: z.array(z.string()).min(1),
      ip_restrictions: z.array(commonSchemas.ipAddress).optional(),
    })
    .strip(),
};

/* ------------------------ Query parameter schemas ------------------------ */

const paginationSchema = commonSchemas.pagination;

const querySchemas = {
  // General search with pagination
  search: z
    .object({
      q: z.string().min(1).max(100).optional(),
    })
    .strip()
    .merge(paginationSchema),

  // Firewall rules query filters
  firewallRules: z
    .object({
      interface: z.enum(['wan', 'lan', 'dmz', 'opt1', 'opt2']).optional(),
      action: z.enum(['pass', 'block', 'reject']).optional(),
      enabled: z.boolean().optional(),
      protocol: commonSchemas.protocol.optional(),
    })
    .strip()
    .merge(paginationSchema),

  // Audit logs query with date range validation
  auditLogs: z
    .object({
      user_id: commonSchemas.id.optional(),
      action: z.string().optional(),
      level: z.enum(['info', 'warning', 'critical', 'security']).optional(),
      start_date: z.string().datetime().optional(),
      end_date: z.string().datetime().optional(),
    })
    .strip()
    .merge(paginationSchema)
    .superRefine((val, ctx) => {
      // Validate date range logic
      if (val.start_date && val.end_date) {
        if (new Date(val.end_date) < new Date(val.start_date)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['end_date'],
            message: 'end_date must be >= start_date',
          });
        }
      }
    }),
};

/* --------------------------- Zod validator middleware --------------------------- */

/**
 * Creates a Zod validation middleware for the specified data source
 * @param {z.ZodSchema} schema - Zod schema to validate against
 * @param {string} source - Data source ('body', 'params', 'query')
 * @returns {Function} Express middleware function
 */
const validateZod = (schema, source = 'body') => {
  return (req, res, next) => {
    // Extract data from the specified source
    const data =
      source === 'body'
        ? req.body
        : source === 'params'
        ? req.params
        : source === 'query'
        ? req.query
        : req[source];

    // Parse and validate data against schema
    const parsed = schema.safeParse(data);

    if (!parsed.success) {
      // FIXED: Robust error handling for validation issues
      let issues = [];
      
      if (parsed.error && parsed.error.issues && Array.isArray(parsed.error.issues)) {
        issues = parsed.error.issues;
      } else if (parsed.error && parsed.error.errors && Array.isArray(parsed.error.errors)) {
        // Fallback for other error formats
        issues = parsed.error.errors;
      } else {
        // Generic fallback for unknown error structures
        issues = [{
          path: [],
          message: parsed.error?.message || 'Validation failed'
        }];
      }

      // Create structured validation error
      const validationError = new ValidationError('Validation failed', {
        validation_errors: issues.map((i) => ({
          field: Array.isArray(i.path) ? i.path.join('.') : String(i.path || ''),
          message: i.message || 'Validation error',
        })),
      });

      // Log validation error for debugging
      logger.warn('Validation error', {
        source,
        errors: validationError.details.validation_errors,
        user_id: req.user?.id,
        ip: req.ip,
      });

      return next(validationError);
    }

    // Replace original data with validated/sanitized data
    if (source === 'body') req.body = parsed.data;
    else if (source === 'params') req.params = parsed.data;
    else if (source === 'query') req.query = parsed.data;
    else req[source] = parsed.data;

    return next();
  };
};

/* --------------------- Express-validator error handler --------------------- */

/**
 * Handles express-validator validation results
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object  
 * @param {Function} next - Express next function
 */
const handleExpressValidation = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    // Convert express-validator errors to our standard format
    const validationError = new ValidationError('Validation failed', {
      validation_errors: errors.array().map((error) => ({
        field: error.path || error.param,
        message: error.msg,
        value: error.value,
      })),
    });

    logger.warn('Express validation error', {
      errors: validationError.details.validation_errors,
      user_id: req.user?.id,
      ip: req.ip,
    });

    return next(validationError);
  }
  
  next();
};

/* --------------------------- Sanitization utilities --------------------------- */

const sanitizers = {
  /**
   * Normalizes string by trimming whitespace and converting to lowercase
   * @param {any} value - Value to normalize
   * @returns {any} Normalized value or original if not string
   */
  normalizeString: (value) => (typeof value === 'string' ? value.trim().toLowerCase() : value),
  
  /**
   * Removes non-alphanumeric characters (with optional allowed chars)
   * @param {any} value - Value to sanitize
   * @param {string} allowed - Additional allowed characters
   * @returns {any} Sanitized value or original if not string
   */
  alphanumeric: (value, allowed = '') => {
    if (typeof value !== 'string') return value;
    const escapedAllowed = allowed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`[^a-zA-Z0-9${escapedAllowed}]`, 'g');
    return value.replace(regex, '');
  },
  
  /**
   * Escapes HTML special characters to prevent XSS
   * @param {any} value - Value to escape
   * @returns {any} Escaped value or original if not string
   */
  escapeHtml: (value) => {
    if (typeof value !== 'string') return value;
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  },
};

/* --------------------------- Custom validators --------------------------- */

const customValidators = {
  isCIDR,
  
  /**
   * Validates port number or port range
   * @param {any} value - Value to validate
   * @returns {boolean} True if valid port or port range
   */
  isPortRange: (value) => {
    if (typeof value === 'number') return value >= 1 && value <= 65535;
    if (typeof value === 'string') {
      // Single port
      if (/^\d+$/.test(value)) {
        const port = parseInt(value, 10);
        return port >= 1 && port <= 65535;
      }
      // Port range (e.g., "8080-8090")
      if (/^\d+-\d+$/.test(value)) {
        const [start, end] = value.split('-').map(Number);
        return start >= 1 && end <= 65535 && start <= end;
      }
    }
    return false;
  },
  
  /**
   * Validates hostname or IP address
   * @param {any} value - Value to validate
   * @returns {boolean} True if valid hostname or IP
   */
  isHostnameOrIP: (value) => {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hostname =
      /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
    return ipv4.test(value) || hostname.test(value) || net.isIP(value) !== 0;
  },
};

/* ---------------------------- Pre-configured validators ---------------------------- */

const validators = {
  // Authentication validators
  login: validateZod(authSchemas.login),
  register: validateZod(authSchemas.register),
  changePassword: validateZod(authSchemas.changePassword),
  refreshToken: validateZod(authSchemas.refreshToken),

  // Firewall rule validators
  createFirewallRule: validateZod(firewallSchemas.createRule),
  updateFirewallRule: validateZod(firewallSchemas.updateRule),
  toggleFirewallRule: validateZod(firewallSchemas.toggleRule),
  bulkFirewallOperation: validateZod(firewallSchemas.bulkOperation),

  // Policy validators
  createPolicy: validateZod(policySchemas.createPolicy),
  updatePolicy: validateZod(policySchemas.updatePolicy),

  // Admin/user management validators
  createUser: validateZod(adminSchemas.createUser),
  updateUser: validateZod(adminSchemas.updateUser),
  createApiKey: validateZod(adminSchemas.createApiKey),

  // Query parameter validators
  searchQuery: validateZod(querySchemas.search, 'query'),
  firewallRulesQuery: validateZod(querySchemas.firewallRules, 'query'),
  auditLogsQuery: validateZod(querySchemas.auditLogs, 'query'),

  // URL parameter validators using express-validator
  idParam: [
    param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
    handleExpressValidation,
  ],
  uuidParam: [
    param('id').isUUID(4).withMessage('ID must be a valid UUID'),
    handleExpressValidation,
  ],
};

/* ------------------------ Dynamic route-based validation ------------------------ */

/**
 * Automatically applies validation based on route path and HTTP method
 * Useful for applying validation without explicitly specifying in routes
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const dynamicValidation = (req, res, next) => {
  const route = req.route?.path || req.path;
  const method = req.method.toLowerCase();

  let validator = null;
  
  // Map route patterns to validators
  if (route.includes('/auth/login') && method === 'post') {
    validator = validators.login;
  } else if (route.includes('/auth/register') && method === 'post') {
    validator = validators.register;
  } else if (route.includes('/firewall/rules') && method === 'post') {
    validator = validators.createFirewallRule;
  } else if (route.includes('/firewall/rules') && method === 'put') {
    validator = validators.updateFirewallRule;
  } else if (route.includes('/policies') && method === 'post') {
    validator = validators.createPolicy;
  }

  // Apply validator if one was found, otherwise continue
  if (validator) return validator(req, res, next);
  next();
};

/* -------------------------------- Module exports -------------------------------- */

module.exports = {
  // Core validation functions
  validateZod,
  handleExpressValidation,
  dynamicValidation,
  
  // Pre-configured validators
  validators,
  
  // Schema definitions
  commonSchemas,
  authSchemas,
  firewallSchemas,
  policySchemas,
  adminSchemas,
  querySchemas,
  
  // Utility functions
  customValidators,
  sanitizers,
};