// src/middleware/validation.js
const { z } = require('zod');
const net = require('node:net');
const { param, validationResult } = require('express-validator');
const { ValidationError } = require('./errorHandler');
const logger = require('../utils/logger');

/* ----------------------- helper & regex ----------------------- */
const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

const isCIDR = (value) => {
  if (!cidrRegex.test(value)) return false;
  const [ip, prefix] = value.split('/');
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => o < 0 || o > 255)) return false;
  const p = Number(prefix);
  return Number.isInteger(p) && p >= 0 && p <= 32;
};

const strongPwd =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;

/* ------------------------- common schemas ------------------------- */
const commonSchemas = {
  uuid: z.string().uuid(),
  id: z.coerce.number().int().positive(),
  ipAddress: z.string().refine((v) => net.isIP(v) !== 0, 'Invalid IP address'),
  port: z.coerce.number().int().min(1).max(65535),
  protocol: z.enum(['tcp', 'udp', 'icmp', 'any']),
  macAddress: z.string().regex(macRegex, 'Invalid MAC address'),

  pagination: z
    .object({
      page: z.coerce.number().int().min(1).default(1),
      limit: z.coerce.number().int().min(1).max(100).default(20),
      sort: z.enum(['asc', 'desc']).default('desc'),
      order_by: z.string().default('created_at'),
    })
    .strip(),

  dateRange: z
    .object({
      start_date: z.string().datetime().optional(),
      end_date: z.string().datetime().optional(),
    })
    .strip()
    .superRefine((val, ctx) => {
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

/* ------------------------- auth schemas ------------------------- */
const authSchemas = {
  login: z
    .object({
      username: z
        .string()
        .min(3)
        .max(30)
        .regex(/^[A-Za-z0-9]+$/, 'Must be alphanumeric'),
      password: z.string().min(8).max(128),
      remember_me: z.boolean().default(false).optional(),
    })
    .strip(),

  register: z
    .object({
      username: z
        .string()
        .min(3)
        .max(30)
        .regex(/^[A-Za-z0-9]+$/, 'Must be alphanumeric'),
      email: z.string().email(),
      password: z.string().min(8).max(128).regex(strongPwd, 'Weak password'),
      confirm_password: z.string().min(8).max(128),
      role: z
        .enum(['admin', 'operator', 'viewer', 'api_user'])
        .default('viewer')
        .optional(),
    })
    .strip()
    .superRefine((val, ctx) => {
      if (val.password !== val.confirm_password) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['confirm_password'],
          message: 'Passwords do not match',
        });
      }
    }),

  changePassword: z
    .object({
      current_password: z.string().min(1),
      new_password: z.string().min(8).max(128).regex(strongPwd, 'Weak password'),
      confirm_password: z.string().min(8).max(128),
    })
    .strip()
    .superRefine((val, ctx) => {
      if (val.new_password !== val.confirm_password) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['confirm_password'],
          message: 'Passwords do not match',
        });
      }
    }),

  refreshToken: z.object({ refresh_token: z.string().min(1) }).strip(),
};

/* ---------------------- firewall rule schemas ---------------------- */
const addressAny = z.object({ type: z.literal('any') }).strip();

const addressSingle = z
  .object({
    type: z.literal('single'),
    address: commonSchemas.ipAddress,
    port: commonSchemas.port.optional(),
  })
  .strip();

const addressNetwork = z
  .object({
    type: z.literal('network'),
    network: z.string().regex(cidrRegex, 'Invalid CIDR').refine(isCIDR, 'Invalid CIDR'),
    port: commonSchemas.port.optional(),
  })
  .strip();

const addressAlias = z
  .object({
    type: z.literal('alias'),
    address: z.string().min(1),
    port: commonSchemas.port.optional(),
  })
  .strip();

const endpointSchema = z.discriminatedUnion('type', [
  addressAny,
  addressSingle,
  addressNetwork,
  addressAlias,
]);

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
  createRule: createRuleBase,
  updateRule: createRuleBase.partial(),
  toggleRule: z
    .object({
      enabled: z.boolean(),
      apply_immediately: z.boolean().default(false).optional(),
    })
    .strip(),
  bulkOperation: z
    .object({
      rule_ids: z.array(commonSchemas.id).min(1).max(50),
      operation: z.enum(['enable', 'disable', 'delete']),
      apply_immediately: z.boolean().default(false).optional(),
    })
    .strip(),
};

/* ------------------------ policy/admin schemas ------------------------ */
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

const conditionsSchema = z
  .object({
    source_ips: z.array(commonSchemas.ipAddress).optional(),
    destination_ips: z.array(commonSchemas.ipAddress).optional(),
    protocols: z.array(commonSchemas.protocol).optional(),
    ports: z.array(commonSchemas.port).optional(),
  })
  .strip();

const policyCreateBase = z
  .object({
    name: z.string().min(3).max(100),
    description: z.string().max(500).optional(),
    type: z.enum(['security', 'access', 'qos', 'custom']),
    rules: z.array(commonSchemas.id).min(1),
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

const adminCreateBase = z
  .object({
    username: z
      .string()
      .min(3)
      .max(30)
      .regex(/^[A-Za-z0-9]+$/, 'Must be alphanumeric'),
    email: z.string().email(),
    password: z.string().min(8).max(128).regex(strongPwd, 'Weak password'),
    role: z.enum(['admin', 'operator', 'viewer', 'api_user']),
    is_active: z.boolean().default(true).optional(),
    permissions: z.array(z.string()).optional(),
  })
  .strip();

const adminSchemas = {
  createUser: adminCreateBase,
  updateUser: adminCreateBase.partial().omit({ password: true }),
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

/* ------------------------ query param schemas ------------------------ */
const paginationSchema = commonSchemas.pagination;

const querySchemas = {
  search: z
    .object({
      q: z.string().min(1).max(100).optional(),
    })
    .strip()
    .merge(paginationSchema),

  firewallRules: z
    .object({
      interface: z.enum(['wan', 'lan', 'dmz', 'opt1', 'opt2']).optional(),
      action: z.enum(['pass', 'block', 'reject']).optional(),
      enabled: z.boolean().optional(),
      protocol: commonSchemas.protocol.optional(),
    })
    .strip()
    .merge(paginationSchema),

  // IMPORTANT: prima merge, poi superRefine (altrimenti merge non esiste)
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

/* --------------------------- zod validator --------------------------- */
const validateZod = (schema, source = 'body') => {
  return (req, res, next) => {
    const data =
      source === 'body'
        ? req.body
        : source === 'params'
        ? req.params
        : source === 'query'
        ? req.query
        : req[source];

    const parsed = schema.safeParse(data);
    if (!parsed.success) {
      const validationError = new ValidationError('Validation failed', {
        validation_errors: parsed.error.errors.map((e) => ({
          field: e.path.join('.'),
          message: e.message,
        })),
      });

      logger.warn('Validation error', {
        source,
        errors: validationError.details.validation_errors,
        user_id: req.user?.id,
        ip: req.ip,
      });

      return next(validationError);
    }

    // sostituisci con i dati validati/sanificati
    if (source === 'body') req.body = parsed.data;
    else if (source === 'params') req.params = parsed.data;
    else if (source === 'query') req.query = parsed.data;
    else req[source] = parsed.data;

    return next();
  };
};

/* --------------------- express-validator handler --------------------- */
const handleExpressValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
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

/* --------------------------- sanitizers + utils --------------------------- */
const sanitizers = {
  normalizeString: (value) => (typeof value === 'string' ? value.trim().toLowerCase() : value),
  alphanumeric: (value, allowed = '') => {
    if (typeof value !== 'string') return value;
    const escapedAllowed = allowed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`[^a-zA-Z0-9${escapedAllowed}]`, 'g');
    return value.replace(regex, '');
  },
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

const customValidators = {
  isCIDR,
  isPortRange: (value) => {
    if (typeof value === 'number') return value >= 1 && value <= 65535;
    if (typeof value === 'string') {
      if (/^\d+$/.test(value)) {
        const port = parseInt(value, 10);
        return port >= 1 && port <= 65535;
      }
      if (/^\d+-\d+$/.test(value)) {
        const [start, end] = value.split('-').map(Number);
        return start >= 1 && end <= 65535 && start <= end;
      }
    }
    return false;
  },
  isHostnameOrIP: (value) => {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hostname =
      /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
    return ipv4.test(value) || hostname.test(value) || net.isIP(value) !== 0;
  },
};

/* ---------------------------- preconfigured ---------------------------- */
const validators = {
  // Auth
  login: validateZod(authSchemas.login),
  register: validateZod(authSchemas.register),
  changePassword: validateZod(authSchemas.changePassword),
  refreshToken: validateZod(authSchemas.refreshToken),

  // Firewall
  createFirewallRule: validateZod(firewallSchemas.createRule),
  updateFirewallRule: validateZod(firewallSchemas.updateRule),
  toggleFirewallRule: validateZod(firewallSchemas.toggleRule),
  bulkFirewallOperation: validateZod(firewallSchemas.bulkOperation),

  // Policy
  createPolicy: validateZod(policySchemas.createPolicy),
  updatePolicy: validateZod(policySchemas.updatePolicy),

  // Admin
  createUser: validateZod(adminSchemas.createUser),
  updateUser: validateZod(adminSchemas.updateUser),
  createApiKey: validateZod(adminSchemas.createApiKey),

  // Query
  searchQuery: validateZod(querySchemas.search, 'query'),
  firewallRulesQuery: validateZod(querySchemas.firewallRules, 'query'),
  auditLogsQuery: validateZod(querySchemas.auditLogs, 'query'),

  // Params con express-validator
  idParam: [
    param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
    handleExpressValidation,
  ],
  uuidParam: [
    param('id').isUUID(4).withMessage('ID must be a valid UUID'),
    handleExpressValidation,
  ],
};

/* ------------------------ dynamic route mapping ------------------------ */
const dynamicValidation = (req, res, next) => {
  const route = req.route?.path || req.path;
  const method = req.method.toLowerCase();

  let validator = null;
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

  if (validator) return validator(req, res, next);
  next();
};

/* -------------------------------- exports -------------------------------- */
module.exports = {
  // Validation middlewares
  validateZod,
  handleExpressValidation,
  dynamicValidation,

  // Pre-configured validators
  validators,

  // Schemas
  commonSchemas,
  authSchemas,
  firewallSchemas,
  policySchemas,
  adminSchemas,
  querySchemas,

  // Utilities
  customValidators,
  sanitizers,
};