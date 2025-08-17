// src/utils/validators.js (or wherever the old Validator was)
const { z } = require('zod');
const logger = require('./logger');

/**
 * Validator class using Zod for data validation
 * Replaces the old Joi-based validator
 */
class Validator {
  /**
   * Validate rule data for create/update operations
   * @param {Object} ruleData - Rule data to validate
   * @returns {Object} Validation result with error/value properties
   */
  static validateRuleData(ruleData) {
    const schema = z.object({
      description: z.string().max(255, 'Description must be 255 characters or less'),
      interface: z.string().max(50, 'Interface must be 50 characters or less'),
      action: z.enum(['allow', 'block', 'reject'], {
        errorMap: () => ({ message: 'Action must be one of: allow, block, reject' })
      }),
      enabled: z.boolean().default(true),
      configuration: z.object({}).passthrough(), // Allow any object structure
      sync_to_opnsense: z.boolean().default(false),
    }).strict();

    try {
      const result = schema.parse(ruleData);
      return { error: null, value: result };
    } catch (error) {
      logger.error('Rule data validation failed', {
        errors: error.errors?.map((err) => `${err.path.join('.')}: ${err.message}`) || [error.message],
        ruleData,
      });

      // Convert Zod error to Joi-like format for compatibility
      return {
        error: {
          details: error.errors?.map((err) => ({
            message: err.message,
            path: err.path,
            type: err.code,
          })) || [{ message: error.message, path: [], type: 'custom' }]
        },
        value: undefined
      };
    }
  }

  /**
   * Validate filters for getRules operations
   * @param {Object} filters - Filter criteria
   * @returns {Object} Validation result with error/value properties
   */
  static validateFilters(filters) {
    const schema = z.object({
      description: z.string().max(255).optional(),
      interface: z.string().max(50).optional(),
      action: z.enum(['allow', 'block', 'reject']).optional(),
      enabled: z.boolean().optional(),
      created_by: z.number().int().positive().optional(),
      start_date: z.string().datetime().optional(),
      end_date: z.string().datetime().optional(),
    }).strict().superRefine((data, ctx) => {
      // Validate that end_date is not before start_date
      if (data.start_date && data.end_date) {
        const startDate = new Date(data.start_date);
        const endDate = new Date(data.end_date);
        if (endDate < startDate) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['end_date'],
            message: 'End date must be after start date',
          });
        }
      }
    });

    try {
      const result = schema.parse(filters);
      return { error: null, value: result };
    } catch (error) {
      logger.error('Filters validation failed', {
        errors: error.errors?.map((err) => `${err.path.join('.')}: ${err.message}`) || [error.message],
        filters,
      });

      // Convert Zod error to Joi-like format for compatibility
      return {
        error: {
          details: error.errors?.map((err) => ({
            message: err.message,
            path: err.path,
            type: err.code,
          })) || [{ message: error.message, path: [], type: 'custom' }]
        },
        value: undefined
      };
    }
  }

  /**
   * Validate pagination parameters
   * @param {Object} pagination - Pagination options
   * @returns {Object} Validation result with error/value properties
   */
  static validatePagination(pagination) {
    const schema = z.object({
      page: z.coerce.number().int().min(1, 'Page must be at least 1').default(1),
      limit: z.coerce.number().int().min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100').default(20),
    }).strict();

    try {
      const result = schema.parse(pagination);
      return { error: null, value: result };
    } catch (error) {
      logger.error('Pagination validation failed', {
        errors: error.errors?.map((err) => `${err.path.join('.')}: ${err.message}`) || [error.message],
        pagination,
      });

      // Convert Zod error to Joi-like format for compatibility
      return {
        error: {
          details: error.errors?.map((err) => ({
            message: err.message,
            path: err.path,
            type: err.code,
          })) || [{ message: error.message, path: [], type: 'custom' }]
        },
        value: undefined
      };
    }
  }

  /**
   * Validate user data for create/update operations
   * @param {Object} userData - User data to validate
   * @returns {Object} Validation result with error/value properties
   */
  static validateUserData(userData) {
    const schema = z.object({
      username: z.string().min(3).max(30).regex(/^[A-Za-z0-9]+$/, 'Username must be alphanumeric'),
      email: z.string().email('Invalid email format'),
      password: z.string().min(8).max(128).optional(),
      role: z.enum(['admin', 'operator', 'viewer']),
      is_active: z.boolean().default(true),
    }).strict();

    try {
      const result = schema.parse(userData);
      return { error: null, value: result };
    } catch (error) {
      logger.error('User data validation failed', {
        errors: error.errors?.map((err) => `${err.path.join('.')}: ${err.message}`) || [error.message],
        userData: { ...userData, password: '[REDACTED]' }, // Don't log passwords
      });

      return {
        error: {
          details: error.errors?.map((err) => ({
            message: err.message,
            path: err.path,
            type: err.code,
          })) || [{ message: error.message, path: [], type: 'custom' }]
        },
        value: undefined
      };
    }
  }

  /**
   * Validate configuration data
   * @param {Object} configData - Configuration data to validate
   * @returns {Object} Validation result with error/value properties
   */
  static validateConfigData(configData) {
    const schema = z.object({
      opnsense_host: z.string().url('Invalid OPNsense host URL'),
      opnsense_api_key: z.string().min(1, 'API key is required'),
      opnsense_api_secret: z.string().min(1, 'API secret is required'),
      sync_enabled: z.boolean().default(true),
      sync_interval: z.number().int().min(60, 'Sync interval must be at least 60 seconds').default(300),
      backup_enabled: z.boolean().default(true),
      backup_retention_days: z.number().int().min(1).max(365).default(30),
    }).strict();

    try {
      const result = schema.parse(configData);
      return { error: null, value: result };
    } catch (error) {
      logger.error('Configuration validation failed', {
        errors: error.errors?.map((err) => `${err.path.join('.')}: ${err.message}`) || [error.message],
        configData: { 
          ...configData, 
          opnsense_api_secret: '[REDACTED]' // Don't log secrets
        },
      });

      return {
        error: {
          details: error.errors?.map((err) => ({
            message: err.message,
            path: err.path,
            type: err.code,
          })) || [{ message: error.message, path: [], type: 'custom' }]
        },
        value: undefined
      };
    }
  }

  /**
   * Validate network address data
   * @param {Object} addressData - Network address data to validate
   * @returns {Object} Validation result with error/value properties
   */
  static validateAddressData(addressData) {
    const schema = z.object({
      name: z.string().min(1).max(100, 'Address name must be 100 characters or less'),
      type: z.enum(['host', 'network', 'range', 'alias']),
      value: z.string().min(1, 'Address value is required'),
      description: z.string().max(255).optional(),
      enabled: z.boolean().default(true),
    }).strict();

    try {
      const result = schema.parse(addressData);
      return { error: null, value: result };
    } catch (error) {
      logger.error('Address data validation failed', {
        errors: error.errors?.map((err) => `${err.path.join('.')}: ${err.message}`) || [error.message],
        addressData,
      });

      return {
        error: {
          details: error.errors?.map((err) => ({
            message: err.message,
            path: err.path,
            type: err.code,
          })) || [{ message: error.message, path: [], type: 'custom' }]
        },
        value: undefined
      };
    }
  }

  /**
   * Helper method to check if validation result has errors
   * @param {Object} result - Validation result
   * @returns {boolean} True if there are validation errors
   */
  static hasErrors(result) {
    return result.error !== null && result.error !== undefined;
  }

  /**
   * Helper method to get formatted error messages
   * @param {Object} result - Validation result
   * @returns {Array} Array of error messages
   */
  static getErrorMessages(result) {
    if (!this.hasErrors(result)) {
      return [];
    }
    
    return result.error.details?.map(detail => detail.message) || [];
  }

  /**
   * Helper method to get first error message
   * @param {Object} result - Validation result
   * @returns {string|null} First error message or null
   */
  static getFirstError(result) {
    const messages = this.getErrorMessages(result);
    return messages.length > 0 ? messages[0] : null;
  }
}

module.exports = Validator;