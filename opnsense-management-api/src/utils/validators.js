const Joi = require('joi');
const logger = require('./logger');

class Validator {
  /**
   * Validate rule data for create/update
   * @param {Object} ruleData - Rule data to validate
   * @returns {Object} Validation result
   */
  static validateRuleData(ruleData) {
    const schema = Joi.object({
      description: Joi.string().max(255).required(),
      interface: Joi.string().max(50).required(),
      action: Joi.string().valid('allow', 'block', 'reject').required(),
      enabled: Joi.boolean().default(true),
      configuration: Joi.object().required(),
      sync_to_opnsense: Joi.boolean().default(false),
    });

    const result = schema.validate(ruleData, { abortEarly: false });

    if (result.error) {
      logger.error('Rule data validation failed', {
        errors: result.error.details.map((detail) => detail.message),
        ruleData,
      });
    }

    return result;
  }

  /**
   * Validate filters for getRules
   * @param {Object} filters - Filter criteria
   * @returns {Object} Validation result
   */
  static validateFilters(filters) {
    const schema = Joi.object({
      description: Joi.string().max(255),
      interface: Joi.string().max(50),
      action: Joi.string().valid('allow', 'block', 'reject'),
      enabled: Joi.boolean(),
      created_by: Joi.number().integer().positive(),
      start_date: Joi.date().iso(),
      end_date: Joi.date().iso().min(Joi.ref('start_date')),
    }).unknown(false);

    const result = schema.validate(filters, { abortEarly: false });

    if (result.error) {
      logger.error('Filters validation failed', {
        errors: result.error.details.map((detail) => detail.message),
        filters,
      });
    }

    return result;
  }

  /**
   * Validate pagination parameters
   * @param {Object} pagination - Pagination options
   * @returns {Object} Validation result
   */
  static validatePagination(pagination) {
    const schema = Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20),
    }).unknown(false);

    const result = schema.validate(pagination, { abortEarly: false });

    if (result.error) {
      logger.error('Pagination validation failed', {
        errors: result.error.details.map((detail) => detail.message),
        pagination,
      });
    }

    return result;
  }
}

module.exports = Validator;