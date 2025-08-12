const { v4: uuidv4 } = require('uuid');
const logger = require('./logger');

/**
 * Generate a cache key from parameters
 * @param {string} prefix - Cache key prefix
 * @param {Object} params - Parameters to include in the key
 * @returns {string} Cache key
 */
function generateCacheKey(prefix, params) {
  try {
    const paramString = JSON.stringify(params, Object.keys(params).sort());
    return `${prefix}_${paramString}`;
  } catch (error) {
    logger.error('Failed to generate cache key', { error: error.message, prefix, params });
    return `${prefix}_default`;
  }
}

/**
 * Format date to ISO string
 * @param {Date|string} date - Date to format
 * @returns {string} ISO formatted date
 */
function formatDate(date) {
  try {
    return new Date(date).toISOString();
  } catch (error) {
    logger.error('Failed to format date', { error: error.message, date });
    return new Date().toISOString();
  }
}

/**
 * Generate a unique identifier
 * @returns {string} UUID
 */
function generateUUID() {
  return uuidv4();
}

/**
 * Check if user has required role
 * @param {Object} user - User object
 * @param {Array<string>} allowedRoles - Allowed roles
 * @returns {boolean} Whether user has required role
 */
async function hasRequiredRole(user, allowedRoles) {
  try {
    const User = require('../models/User');
    const foundUser = await User.findByPk(user.id);
    if (!foundUser) {
      logger.error('User not found for role check', { user_id: user.id });
      return false;
    }
    const hasRole = allowedRoles.includes(foundUser.role);
    if (!hasRole) {
      logger.warn('User does not have required role', {
        user_id: user.id,
        username: foundUser.username,
        required_roles: allowedRoles,
      });
    }
    return hasRole;
  } catch (error) {
    logger.error('Failed to check user role', {
      error: error.message,
      user_id: user.id,
      allowed_roles: allowedRoles,
    });
    return false;
  }
}

/**
 * Calculate response time in minutes
 * @param {Date|string} start - Start time
 * @param {Date|string} end - End time
 * @returns {number|null} Response time in minutes
 */
function calculateResponseTime(start, end) {
  try {
    const startTime = new Date(start);
    const endTime = new Date(end);
    if (isNaN(startTime) || isNaN(endTime)) {
      return null;
    }
    return (endTime - startTime) / (1000 * 60);
  } catch (error) {
    logger.error('Failed to calculate response time', { error: error.message, start, end });
    return null;
  }
}

module.exports = {
  generateCacheKey,
  formatDate,
  generateUUID,
  hasRequiredRole,
  calculateResponseTime,
};