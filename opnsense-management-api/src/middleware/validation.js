const Joi = require('joi');
const { param, validationResult } = require('express-validator');
const { ValidationError } = require('./errorHandler');
const logger = require('../utils/logger');

// Common validation schemas
const commonSchemas = {
  // UUID validation
  uuid: Joi.string().uuid({ version: 'uuidv4' }),
  
  // Object ID validation (for database IDs)
  id: Joi.number().integer().positive(),
  
  // Pagination schemas
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sort: Joi.string().valid('asc', 'desc').default('desc'),
    order_by: Joi.string().default('created_at'),
  }),
  
  // Date range schemas
  dateRange: Joi.object({
    start_date: Joi.date().iso(),
    end_date: Joi.date().iso().min(Joi.ref('start_date')),
  }),
  
  // IP address validation
  ipAddress: Joi.string().ip({ version: ['ipv4', 'ipv6'] }),
  
  // Port validation
  port: Joi.number().integer().min(1).max(65535),
  
  // Network protocol validation
  protocol: Joi.string().valid('tcp', 'udp', 'icmp', 'any'),
  
  // MAC address validation
  macAddress: Joi.string().pattern(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
};

// Authentication validation schemas
const authSchemas = {
  login: Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(8).max(128).required(),
    remember_me: Joi.boolean().default(false),
  }),
  
  register: Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      }),
    confirm_password: Joi.string().valid(Joi.ref('password')).required()
      .messages({
        'any.only': 'Passwords do not match',
      }),
    role: Joi.string().valid('admin', 'operator', 'viewer', 'api_user').default('viewer'),
  }),
  
  changePassword: Joi.object({
    current_password: Joi.string().required(),
    new_password: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required(),
    confirm_password: Joi.string().valid(Joi.ref('new_password')).required(),
  }),
  
  refreshToken: Joi.object({
    refresh_token: Joi.string().required(),
  }),
};

// Firewall rule validation schemas
const firewallSchemas = {
  createRule: Joi.object({
    description: Joi.string().max(255).required(),
    interface: Joi.string().valid('wan', 'lan', 'dmz', 'opt1', 'opt2').required(),
    direction: Joi.string().valid('in', 'out').default('in'),
    action: Joi.string().valid('pass', 'block', 'reject').required(),
    protocol: commonSchemas.protocol.required(),
    source: Joi.object({
      type: Joi.string().valid('any', 'single', 'network', 'alias').default('any'),
      address: Joi.when('type', {
        is: 'single',
        then: commonSchemas.ipAddress.required(),
        otherwise: Joi.string(),
      }),
      network: Joi.when('type', {
        is: 'network',
        then: Joi.string().pattern(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/).required(),
        otherwise: Joi.string(),
      }),
      port: Joi.when('type', {
        is: Joi.valid('single', 'network'),
        then: commonSchemas.port,
        otherwise: Joi.forbidden(),
      }),
    }).required(),
    destination: Joi.object({
      type: Joi.string().valid('any', 'single', 'network', 'alias').default('any'),
      address: Joi.when('type', {
        is: 'single',
        then: commonSchemas.ipAddress.required(),
        otherwise: Joi.string(),
      }),
      network: Joi.when('type', {
        is: 'network',
        then: Joi.string().pattern(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/).required(),
        otherwise: Joi.string(),
      }),
      port: Joi.when('type', {
        is: Joi.valid('single', 'network'),
        then: commonSchemas.port,
        otherwise: Joi.forbidden(),
      }),
    }).required(),
    enabled: Joi.boolean().default(true),
    log: Joi.boolean().default(false),
    sequence: Joi.number().integer().min(1).max(9999),
  }),
  
  updateRule: Joi.object({
    description: Joi.string().max(255),
    interface: Joi.string().valid('wan', 'lan', 'dmz', 'opt1', 'opt2'),
    direction: Joi.string().valid('in', 'out'),
    action: Joi.string().valid('pass', 'block', 'reject'),
    protocol: commonSchemas.protocol,
    source: Joi.object({
      type: Joi.string().valid('any', 'single', 'network', 'alias'),
      address: Joi.when('type', {
        is: 'single',
        then: commonSchemas.ipAddress,
        otherwise: Joi.string(),
      }),
      network: Joi.when('type', {
        is: 'network',
        then: Joi.string().pattern(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/),
        otherwise: Joi.string(),
      }),
      port: commonSchemas.port,
    }),
    destination: Joi.object({
      type: Joi.string().valid('any', 'single', 'network', 'alias'),
      address: Joi.when('type', {
        is: 'single',
        then: commonSchemas.ipAddress,
        otherwise: Joi.string(),
      }),
      network: Joi.when('type', {
        is: 'network',
        then: Joi.string().pattern(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/),
        otherwise: Joi.string(),
      }),
      port: commonSchemas.port,
    }),
    enabled: Joi.boolean(),
    log: Joi.boolean(),
    sequence: Joi.number().integer().min(1).max(9999),
  }),
  
  toggleRule: Joi.object({
    enabled: Joi.boolean().required(),
    apply_immediately: Joi.boolean().default(false),
  }),
  
  bulkOperation: Joi.object({
    rule_ids: Joi.array().items(commonSchemas.id).min(1).max(50).required(),
    operation: Joi.string().valid('enable', 'disable', 'delete').required(),
    apply_immediately: Joi.boolean().default(false),
  }),
};

// Policy validation schemas
const policySchemas = {
  createPolicy: Joi.object({
    name: Joi.string().min(3).max(100).required(),
    description: Joi.string().max(500),
    type: Joi.string().valid('security', 'access', 'qos', 'custom').required(),
    rules: Joi.array().items(commonSchemas.id).min(1).required(),
    enabled: Joi.boolean().default(true),
    priority: Joi.number().integer().min(1).max(100).default(50),
    schedule: Joi.object({
      enabled: Joi.boolean().default(false),
      start_time: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
      end_time: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
      days: Joi.array().items(Joi.string().valid('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday')),
    }),
    conditions: Joi.object({
      source_ips: Joi.array().items(commonSchemas.ipAddress),
      destination_ips: Joi.array().items(commonSchemas.ipAddress),
      protocols: Joi.array().items(commonSchemas.protocol),
      ports: Joi.array().items(commonSchemas.port),
    }),
  }),
  
  updatePolicy: Joi.object({
    name: Joi.string().min(3).max(100),
    description: Joi.string().max(500),
    type: Joi.string().valid('security', 'access', 'qos', 'custom'),
    rules: Joi.array().items(commonSchemas.id),
    enabled: Joi.boolean(),
    priority: Joi.number().integer().min(1).max(100),
    schedule: Joi.object({
      enabled: Joi.boolean(),
      start_time: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
      end_time: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
      days: Joi.array().items(Joi.string().valid('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday')),
    }),
    conditions: Joi.object({
      source_ips: Joi.array().items(commonSchemas.ipAddress),
      destination_ips: Joi.array().items(commonSchemas.ipAddress),
      protocols: Joi.array().items(commonSchemas.protocol),
      ports: Joi.array().items(commonSchemas.port),
    }),
  }),
};

// Admin validation schemas
const adminSchemas = {
  createUser: Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required(),
    role: Joi.string().valid('admin', 'operator', 'viewer', 'api_user').required(),
    is_active: Joi.boolean().default(true),
    permissions: Joi.array().items(Joi.string()),
  }),
  
  updateUser: Joi.object({
    username: Joi.string().alphanum().min(3).max(30),
    email: Joi.string().email(),
    role: Joi.string().valid('admin', 'operator', 'viewer', 'api_user'),
    is_active: Joi.boolean(),
    permissions: Joi.array().items(Joi.string()),
  }),
  
  createApiKey: Joi.object({
    name: Joi.string().min(3).max(100).required(),
    description: Joi.string().max(500),
    expires_at: Joi.date().min('now'),
    permissions: Joi.array().items(Joi.string()).required(),
    ip_restrictions: Joi.array().items(commonSchemas.ipAddress),
  }),
};

// Query parameter schemas
const querySchemas = {
  search: Joi.object({
    q: Joi.string().min(1).max(100),
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sort: Joi.string().valid('asc', 'desc').default('desc'),
    order_by: Joi.string().default('created_at'),
  }),
  
  firewallRules: Joi.object({
    interface: Joi.string().valid('wan', 'lan', 'dmz', 'opt1', 'opt2'),
    action: Joi.string().valid('pass', 'block', 'reject'),
    enabled: Joi.boolean(),
    protocol: commonSchemas.protocol,
    ...commonSchemas.pagination,
  }),
  
  auditLogs: Joi.object({
    user_id: commonSchemas.id,
    action: Joi.string(),
    level: Joi.string().valid('info', 'warning', 'critical', 'security'),
    start_date: Joi.date().iso(),
    end_date: Joi.date().iso().min(Joi.ref('start_date')),
    ...commonSchemas.pagination,
  }),
};

/**
 * Create Joi validation middleware
 */
const validateJoi = (schema, source = 'body') => {
  return (req, res, next) => {
    const data = source === 'body' ? req.body : 
                  source === 'params' ? req.params :
                  source === 'query' ? req.query : req[source];
    
    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true,
      convert: true,
    });
    
    if (error) {
      const validationError = new ValidationError('Validation failed', {
        validation_errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value,
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
    
    // Replace the source data with validated and sanitized data
    if (source === 'body') req.body = value;
    else if (source === 'params') req.params = value;
    else if (source === 'query') req.query = value;
    else req[source] = value;
    
    next();
  };
};

/**
 * Express-validator based validation middleware
 */
const handleExpressValidation = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const validationError = new ValidationError('Validation failed', {
      validation_errors: errors.array().map(error => ({
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

/**
 * Custom validation functions
 */
const customValidators = {
  // Validate network CIDR notation
  isCIDR: (value) => {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrRegex.test(value)) return false;
    
    const [ip, prefix] = value.split('/');
    const prefixNum = parseInt(prefix);
    
    // Validate IP octets
    const octets = ip.split('.').map(Number);
    if (octets.some(octet => octet < 0 || octet > 255)) return false;
    
    // Validate prefix
    return prefixNum >= 0 && prefixNum <= 32;
  },
  
  // Validate port range
  isPortRange: (value) => {
    if (typeof value === 'number') {
      return value >= 1 && value <= 65535;
    }
    
    if (typeof value === 'string') {
      if (/^\d+$/.test(value)) {
        const port = parseInt(value);
        return port >= 1 && port <= 65535;
      }
      
      if (/^\d+-\d+$/.test(value)) {
        const [start, end] = value.split('-').map(Number);
        return start >= 1 && end <= 65535 && start <= end;
      }
    }
    
    return false;
  },
  
  // Validate hostname or IP
  isHostnameOrIP: (value) => {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hostnameRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
    
    return ipRegex.test(value) || hostnameRegex.test(value);
  },
};

/**
 * Sanitization functions
 */
const sanitizers = {
  // Trim whitespace and convert to lowercase
  normalizeString: (value) => {
    if (typeof value !== 'string') return value;
    return value.trim().toLowerCase();
  },
  
  // Remove non-alphanumeric characters except specified
  alphanumeric: (value, allowed = '') => {
    if (typeof value !== 'string') return value;
    const escapedAllowed = allowed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`[^a-zA-Z0-9${escapedAllowed}]`, 'g');
    return value.replace(regex, '');
  },
  
  // Sanitize HTML to prevent XSS
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

/**
 * Pre-configured validation middlewares
 */
const validators = {
  // Authentication validators
  login: validateJoi(authSchemas.login),
  register: validateJoi(authSchemas.register),
  changePassword: validateJoi(authSchemas.changePassword),
  refreshToken: validateJoi(authSchemas.refreshToken),
  
  // Firewall validators
  createFirewallRule: validateJoi(firewallSchemas.createRule),
  updateFirewallRule: validateJoi(firewallSchemas.updateRule),
  toggleFirewallRule: validateJoi(firewallSchemas.toggleRule),
  bulkFirewallOperation: validateJoi(firewallSchemas.bulkOperation),
  
  // Policy validators
  createPolicy: validateJoi(policySchemas.createPolicy),
  updatePolicy: validateJoi(policySchemas.updatePolicy),
  
  // Admin validators
  createUser: validateJoi(adminSchemas.createUser),
  updateUser: validateJoi(adminSchemas.updateUser),
  createApiKey: validateJoi(adminSchemas.createApiKey),
  
  // Query validators
  searchQuery: validateJoi(querySchemas.search, 'query'),
  firewallRulesQuery: validateJoi(querySchemas.firewallRules, 'query'),
  auditLogsQuery: validateJoi(querySchemas.auditLogs, 'query'),
  
  // Parameter validators
  idParam: [
    param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
    handleExpressValidation,
  ],
  
  uuidParam: [
    param('id').isUUID(4).withMessage('ID must be a valid UUID'),
    handleExpressValidation,
  ],
};

/**
 * Dynamic validation based on request context
 */
const dynamicValidation = (req, res, next) => {
  const route = req.route?.path || req.path;
  const method = req.method.toLowerCase();
  
  let validator = null;
  
  // Map routes to validators
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
  
  if (validator) {
    return validator(req, res, next);
  }
  
  next();
};

module.exports = {
  // Validation middlewares
  validateJoi,
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