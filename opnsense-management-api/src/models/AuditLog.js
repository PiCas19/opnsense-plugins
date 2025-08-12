const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class AuditLog extends Model {
  /**
   * Check if this is a security-related audit entry
   */
  isSecurityEvent() {
    return this.level === 'security' || this.level === 'critical';
  }

  /**
   * Check if this is a failed operation
   */
  isFailed() {
    return this.status_code >= 400;
  }

  /**
   * Get duration in milliseconds
   */
  getDuration() {
    return this.response_time || 0;
  }

  /**
   * Format for security report
   */
  toSecurityReport() {
    return {
      id: this.audit_id,
      timestamp: this.timestamp,
      action: this.action,
      user: this.username,
      ip: this.client_ip,
      status: this.status_code,
      url: this.url,
      method: this.method,
      level: this.level,
      details: this.security_details,
    };
  }

  /**
   * Check if IP address should be flagged
   */
  shouldFlagIP() {
    return this.isFailed() && 
           (this.action.includes('login') || 
            this.action.includes('auth') ||
            this.status_code === 403 ||
            this.status_code === 401);
  }

  /**
   * Get risk score based on audit data
   */
  getRiskScore() {
    let score = 0;
    
    // Base score by level
    const levelScores = {
      'info': 1,
      'warning': 3,
      'critical': 7,
      'security': 10,
    };
    score += levelScores[this.level] || 1;
    
    // Increase score for failed operations
    if (this.isFailed()) score += 5;
    
    // Increase score for authentication failures
    if (this.action.includes('login') && this.isFailed()) score += 10;
    
    // Increase score for admin actions
    if (this.action.includes('admin')) score += 3;
    
    // Increase score for critical firewall changes
    if (this.action.includes('rule') && this.method === 'DELETE') score += 5;
    
    return Math.min(score, 100); // Cap at 100
  }
}

AuditLog.init({
  id: {
    type: DataTypes.BIGINT,
    primaryKey: true,
    autoIncrement: true,
  },
  
  // Unique audit identifier
  audit_id: {
    type: DataTypes.UUID,
    allowNull: false,
    unique: true,
    comment: 'Unique identifier for this audit entry',
  },
  
  // Timing
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
    comment: 'When the event occurred',
  },
  
  // Event classification
  level: {
    type: DataTypes.ENUM('info', 'warning', 'critical', 'security'),
    allowNull: false,
    defaultValue: 'info',
    comment: 'Severity level of the audit event',
  },
  
  action: {
    type: DataTypes.STRING(100),
    allowNull: false,
    comment: 'Action that was performed',
  },
  
  // User information
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'ID of the user who performed the action',
  },
  
  username: {
    type: DataTypes.STRING(100),
    allowNull: false,
    defaultValue: 'anonymous',
    comment: 'Username who performed the action',
  },
  
  // Network information
  client_ip: {
    type: DataTypes.INET,
    allowNull: false,
    comment: 'IP address of the client',
  },
  
  user_agent: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'User agent string from the request',
  },
  
  // Request information
  method: {
    type: DataTypes.STRING(10),
    allowNull: false,
    comment: 'HTTP method (GET, POST, PUT, DELETE, etc.)',
  },
  
  url: {
    type: DataTypes.TEXT,
    allowNull: false,
    comment: 'Full URL that was requested',
  },
  
  path: {
    type: DataTypes.STRING(500),
    allowNull: false,
    comment: 'Path portion of the URL',
  },
  
  // Request/Response data
  query: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Query parameters (sanitized)',
  },
  
  body: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Request body (sanitized)',
  },
  
  headers: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Request headers (sanitized)',
  },
  
  response_body: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Response body (if captured)',
  },
  
  // Response information
  status_code: {
    type: DataTypes.INTEGER,
    allowNull: false,
    comment: 'HTTP status code of the response',
  },
  
  response_time: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Response time in milliseconds',
  },
  
  request_size: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Size of the request in bytes',
  },
  
  response_size: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Size of the response in bytes',
  },
  
  // Session information
  session_id: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Session ID if available',
  },
  
  correlation_id: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'Correlation ID for tracking related requests',
  },
  
  // Security-specific fields
  authentication_method: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Authentication method used (jwt, api_key, session)',
  },
  
  authorization_result: {
    type: DataTypes.ENUM('granted', 'denied', 'not_required'),
    allowNull: true,
    comment: 'Result of authorization check',
  },
  
  security_details: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Additional security-related details',
  },
  
  // Risk assessment
  risk_score: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0,
      max: 100,
    },
    comment: 'Calculated risk score (0-100)',
  },
  
  risk_factors: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Factors that contributed to risk score',
  },
  
  // Context information
  before_state: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'State before the change (for modifications)',
  },
  
  after_state: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'State after the change (for modifications)',
  },
  
  changes: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Summary of what changed',
  },
  
  // Tags and categorization
  tags: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Tags for categorizing audit entries',
  },
  
  category: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Category of the audit event',
  },
  
  // External references
  related_entity_type: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Type of related entity (rule, policy, user, etc.)',
  },
  
  related_entity_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'ID of related entity',
  },
  
  // Compliance and retention
  retention_period: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 2555, // ~7 years in days
    comment: 'How long to retain this audit log (in days)',
  },
  
  compliance_tags: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Compliance frameworks this audit entry relates to',
  },
  
  // Processing status
  processed: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether this audit log has been processed by analysis systems',
  },
  
  processed_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When this audit log was processed',
  },
  
  // Additional metadata
  metadata: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Additional metadata for the audit entry',
  },
}, {
  sequelize,
  modelName: 'AuditLog',
  tableName: 'audit_logs',
  timestamps: false, // We manage timestamp manually
  indexes: [
    {
      fields: ['timestamp'],
      name: 'idx_audit_logs_timestamp',
    },
    {
      fields: ['audit_id'],
      unique: true,
      name: 'idx_audit_logs_audit_id',
    },
    {
      fields: ['level', 'timestamp'],
      name: 'idx_audit_logs_level_timestamp',
    },
    {
      fields: ['action', 'timestamp'],
      name: 'idx_audit_logs_action_timestamp',
    },
    {
      fields: ['user_id', 'timestamp'],
      name: 'idx_audit_logs_user_timestamp',
    },
    {
      fields: ['client_ip', 'timestamp'],
      name: 'idx_audit_logs_ip_timestamp',
    },
    {
      fields: ['status_code', 'timestamp'],
      name: 'idx_audit_logs_status_timestamp',
    },
    {
      fields: ['correlation_id'],
      name: 'idx_audit_logs_correlation',
    },
    {
      fields: ['related_entity_type', 'related_entity_id'],
      name: 'idx_audit_logs_related_entity',
    },
    {
      // Composite index for security events
      fields: ['level', 'status_code', 'timestamp'],
      name: 'idx_audit_logs_security',
      where: {
        level: ['security', 'critical'],
      },
    },
    {
      // GIN index for JSONB queries
      fields: ['query'],
      using: 'gin',
      name: 'idx_audit_logs_query',
    },
    {
      fields: ['body'],
      using: 'gin',
      name: 'idx_audit_logs_body',
    },
    {
      fields: ['security_details'],
      using: 'gin',
      name: 'idx_audit_logs_security_details',
    },
    {
      fields: ['metadata'],
      using: 'gin',
      name: 'idx_audit_logs_metadata',
    },
    {
      // GIN index for array queries
      fields: ['tags'],
      using: 'gin',
      name: 'idx_audit_logs_tags',
    },
    {
      fields: ['risk_factors'],
      using: 'gin',
      name: 'idx_audit_logs_risk_factors',
    },
    {
      fields: ['compliance_tags'],
      using: 'gin',
      name: 'idx_audit_logs_compliance',
    },
    {
      // Index for cleanup operations
      fields: ['timestamp', 'retention_period'],
      name: 'idx_audit_logs_cleanup',
    },
  ],
  scopes: {
    security: {
      where: {
        level: ['security', 'critical'],
      },
    },
    failed: {
      where: {
        status_code: {
          [sequelize.Sequelize.Op.gte]: 400,
        },
      },
    },
    recent: {
      where: {
        timestamp: {
          [sequelize.Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        },
      },
    },
    highRisk: {
      where: {
        risk_score: {
          [sequelize.Sequelize.Op.gte]: 70,
        },
      },
    },
    byUser: (userId) => ({
      where: {
        user_id: userId,
      },
    }),
    byIP: (ip) => ({
      where: {
        client_ip: ip,
      },
    }),
    byAction: (action) => ({
      where: {
        action: {
          [sequelize.Sequelize.Op.iLike]: `%${action}%`,
        },
      },
    }),
  },
});

// Hooks to calculate risk score before saving
AuditLog.beforeCreate((auditLog) => {
  auditLog.risk_score = auditLog.getRiskScore();
});

AuditLog.beforeUpdate((auditLog) => {
  auditLog.risk_score = auditLog.getRiskScore();
});

// Class methods
AuditLog.findSecurityEvents = function(limit = 100) {
  return this.scope('security').findAll({
    limit,
    order: [['timestamp', 'DESC']],
  });
};

AuditLog.findFailedRequests = function(hours = 24) {
  return this.scope(['failed', 'recent']).findAll({
    where: {
      timestamp: {
        [sequelize.Sequelize.Op.gte]: new Date(Date.now() - hours * 60 * 60 * 1000),
      },
    },
    order: [['timestamp', 'DESC']],
  });
};

AuditLog.findByCorrelationId = function(correlationId) {
  return this.findAll({
    where: { correlation_id: correlationId },
    order: [['timestamp', 'ASC']],
  });
};

AuditLog.getSecurityStatistics = async function(hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  
  const stats = await this.findAll({
    attributes: [
      'level',
      'action',
      [sequelize.fn('COUNT', '*'), 'count'],
      [sequelize.fn('AVG', sequelize.col('risk_score')), 'avg_risk'],
    ],
    where: {
      timestamp: {
        [sequelize.Sequelize.Op.gte]: since,
      },
    },
    group: ['level', 'action'],
    raw: true,
  });

  return stats;
};

AuditLog.findSuspiciousActivity = async function(hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  
  return this.findAll({
    where: {
      timestamp: {
        [sequelize.Sequelize.Op.gte]: since,
      },
      [sequelize.Sequelize.Op.or]: [
        { risk_score: { [sequelize.Sequelize.Op.gte]: 70 } },
        { level: 'security' },
        { 
          status_code: { [sequelize.Sequelize.Op.in]: [401, 403] },
          action: { [sequelize.Sequelize.Op.iLike]: '%login%' },
        },
      ],
    },
    order: [['risk_score', 'DESC'], ['timestamp', 'DESC']],
  });
};

// Cleanup method for old audit logs
AuditLog.cleanup = async function() {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - 2555); // Default 7 years

  const deleted = await this.destroy({
    where: {
      timestamp: {
        [sequelize.Sequelize.Op.lt]: cutoffDate,
      },
      // Don't delete security events
      level: {
        [sequelize.Sequelize.Op.notIn]: ['security', 'critical'],
      },
    },
  });

  return deleted;
};

module.exports = AuditLog;