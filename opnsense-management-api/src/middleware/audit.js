const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

// Audit log levels
const AUDIT_LEVELS = {
  INFO: 'info',
  WARNING: 'warning',
  CRITICAL: 'critical',
  SECURITY: 'security',
};

// Actions that require audit logging
const AUDITED_ACTIONS = {
  LOGIN: 'login',
  LOGOUT: 'logout',
  RULE_CREATE: 'rule_create',
  RULE_UPDATE: 'rule_update',
  RULE_DELETE: 'rule_delete',
  RULE_TOGGLE: 'rule_toggle',
  POLICY_CREATE: 'policy_create',
  POLICY_UPDATE: 'policy_update',
  POLICY_DELETE: 'policy_delete',
  CONFIG_CHANGE: 'config_change',
  SYSTEM_ACCESS: 'system_access',
  API_ACCESS: 'api_access',
  ADMIN_ACTION: 'admin_action',
};

// Sensitive fields to mask in logs
const SENSITIVE_FIELDS = [
  'password',
  'secret',
  'token',
  'key',
  'authorization',
  'cookie',
  'session',
  'api_key',
  'api_secret',
];

/**
 * Mask sensitive data in objects
 */
const maskSensitiveData = (obj) => {
  if (!obj || typeof obj !== 'object') return obj;
  
  const masked = { ...obj };
  
  for (const key in masked) {
    if (SENSITIVE_FIELDS.some(field => key.toLowerCase().includes(field))) {
      masked[key] = '***MASKED***';
    } else if (typeof masked[key] === 'object' && masked[key] !== null) {
      masked[key] = maskSensitiveData(masked[key]);
    }
  }
  
  return masked;
};

/**
 * Get client IP address with proxy support
 */
const getClientIP = (req) => {
  return req.ip ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         'unknown';
};

/**
 * Get user agent information
 */
const getUserAgent = (req) => {
  return req.get('User-Agent') || 'unknown';
};

/**
 * Determine if request should be audited
 */
const shouldAudit = (req, res) => {
  // Always audit authentication endpoints
  if (req.path.includes('/auth/')) return true;
  
  // Always audit admin actions
  if (req.path.includes('/admin/')) return true;
  
  // Always audit firewall rule changes
  if (req.path.includes('/firewall/') && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return true;
  }
  
  // Audit policy changes
  if (req.path.includes('/policies/') && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return true;
  }
  
  // Audit failed requests
  if (res.statusCode >= 400) return true;
  
  // Audit based on custom header
  if (req.headers['x-audit-required'] === 'true') return true;
  
  return false;
};

/**
 * Create audit log entry
 */
const createAuditEntry = (req, res, action, level = AUDIT_LEVELS.INFO, additionalData = {}) => {
  const auditId = uuidv4();
  const timestamp = new Date().toISOString();
  const clientIP = getClientIP(req);
  const userAgent = getUserAgent(req);
  
  const auditEntry = {
    audit_id: auditId,
    timestamp,
    level,
    action,
    user_id: req.user?.id || null,
    username: req.user?.username || 'anonymous',
    client_ip: clientIP,
    user_agent: userAgent,
    method: req.method,
    url: req.originalUrl || req.url,
    path: req.path,
    query: maskSensitiveData(req.query),
    body: maskSensitiveData(req.body),
    headers: maskSensitiveData(req.headers),
    status_code: res.statusCode,
    response_time: res.responseTime || null,
    session_id: req.sessionID || null,
    correlation_id: req.correlationId || auditId,
    ...additionalData,
  };
  
  return auditEntry;
};

/**
 * Save audit entry to database
 */
const saveAuditEntry = async (auditEntry) => {
  try {
    // Try to save to database
    const AuditLog = require('../models/AuditLog');
    await AuditLog.create(auditEntry);
    
    logger.info('Audit entry saved to database', { 
      audit_id: auditEntry.audit_id,
      action: auditEntry.action,
      user: auditEntry.username,
    });
  } catch (error) {
    // Fallback to file logging if database fails
    logger.error('Failed to save audit entry to database', {
      error: error.message,
      audit_id: auditEntry.audit_id,
    });
    
    // Log to file as backup
    logger.audit('AUDIT_ENTRY', auditEntry);
  }
};

/**
 * Main audit middleware
 */
const auditMiddleware = (options = {}) => {
  const {
    includeRequestBody = true,
    includeResponseBody = false,
    maxBodySize = 10000, // 10KB
    excludePaths = ['/health', '/metrics'],
    customAuditCheck = null,
  } = options;
  
  return async (req, res, next) => {
    // Skip excluded paths
    if (excludePaths.some(path => req.path.startsWith(path))) {
      return next();
    }
    
    // Add correlation ID for request tracking
    req.correlationId = req.headers['x-correlation-id'] || uuidv4();
    res.setHeader('X-Correlation-ID', req.correlationId);
    
    // Record start time for response time calculation
    const startTime = Date.now();
    
    // Store original res.json to capture response body if needed
    const originalJson = res.json;
    let responseBody = null;
    
    if (includeResponseBody) {
      res.json = function(body) {
        responseBody = body;
        return originalJson.call(this, body);
      };
    }
    
    // Hook into response finish event
    res.on('finish', async () => {
      try {
        // Calculate response time
        res.responseTime = Date.now() - startTime;
        
        // Check if this request should be audited
        const shouldAuditRequest = customAuditCheck ? 
          customAuditCheck(req, res) : 
          shouldAudit(req, res);
        
        if (!shouldAuditRequest) return;
        
        // Determine audit level based on status code
        let level = AUDIT_LEVELS.INFO;
        if (res.statusCode >= 400 && res.statusCode < 500) {
          level = AUDIT_LEVELS.WARNING;
        } else if (res.statusCode >= 500) {
          level = AUDIT_LEVELS.CRITICAL;
        }
        
        // Determine action based on request
        let action = AUDITED_ACTIONS.API_ACCESS;
        if (req.path.includes('/auth/login')) action = AUDITED_ACTIONS.LOGIN;
        else if (req.path.includes('/auth/logout')) action = AUDITED_ACTIONS.LOGOUT;
        else if (req.path.includes('/firewall/') && req.method !== 'GET') {
          if (req.method === 'POST') action = AUDITED_ACTIONS.RULE_CREATE;
          else if (req.method === 'PUT' || req.method === 'PATCH') {
            action = req.path.includes('/toggle') ? 
              AUDITED_ACTIONS.RULE_TOGGLE : 
              AUDITED_ACTIONS.RULE_UPDATE;
          }
          else if (req.method === 'DELETE') action = AUDITED_ACTIONS.RULE_DELETE;
        }
        else if (req.path.includes('/admin/')) action = AUDITED_ACTIONS.ADMIN_ACTION;
        
        // Additional audit data
        const additionalData = {
          request_size: req.get('content-length') || 0,
          response_size: res.get('content-length') || 0,
        };
        
        if (includeResponseBody && responseBody && JSON.stringify(responseBody).length <= maxBodySize) {
          additionalData.response_body = maskSensitiveData(responseBody);
        }
        
        // Create and save audit entry
        const auditEntry = createAuditEntry(req, res, action, level, additionalData);
        await saveAuditEntry(auditEntry);
        
        // Record security events
        if (level === AUDIT_LEVELS.CRITICAL || res.statusCode === 401 || res.statusCode === 403) {
          try {
            const { metricsHelpers } = require('../config/monitoring');
            metricsHelpers.recordSecurityAlert(
              level === AUDIT_LEVELS.CRITICAL ? 'critical' : 'warning',
              'authentication',
              'api'
            );
          } catch (error) {
            // Monitoring not available
          }
        }
        
      } catch (error) {
        logger.error('Audit middleware error', {
          error: error.message,
          correlation_id: req.correlationId,
        });
      }
    });
    
    next();
  };
};

/**
 * Manual audit logging function
 */
const auditLog = async (req, action, level = AUDIT_LEVELS.INFO, additionalData = {}) => {
  try {
    const auditEntry = createAuditEntry(
      req, 
      { statusCode: 200 }, // Mock response for manual logs
      action, 
      level, 
      additionalData
    );
    
    await saveAuditEntry(auditEntry);
    return auditEntry.audit_id;
  } catch (error) {
    logger.error('Manual audit log error', { error: error.message, action });
    return null;
  }
};

/**
 * Security event audit function
 */
const auditSecurityEvent = async (req, eventType, severity = 'medium', details = {}) => {
  const action = `security_event_${eventType}`;
  const level = severity === 'high' ? AUDIT_LEVELS.CRITICAL : 
                severity === 'medium' ? AUDIT_LEVELS.WARNING : 
                AUDIT_LEVELS.INFO;
  
  return await auditLog(req, action, level, {
    event_type: eventType,
    severity,
    security_details: details,
  });
};

module.exports = {
  auditMiddleware,
  auditLog,
  auditSecurityEvent,
  AUDIT_LEVELS,
  AUDITED_ACTIONS,
  maskSensitiveData,
  getClientIP,
  getUserAgent,
};