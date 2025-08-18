const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Alert extends Model {
  /**
   * Check if the alert is still active
   */
  isActive() {
    return this.status === 'active' && !this.acknowledged_at;
  }

  /**
   * Check if the alert is critical
   */
  isCritical() {
    return this.severity === 'critical';
  }

  /**
   * Mark the alert as acknowledged
   */
  async acknowledge(userId, note = null) {
    return await this.update({
      acknowledged_at: new Date(),
      acknowledged_by: userId,
      acknowledgment_note: note,
      status: 'acknowledged',
    });
  }

  /**
   * Mark the alert as resolved
   */
  async resolve(userId, resolution = null) {
    return await this.update({
      resolved_at: new Date(),
      resolved_by: userId,
      resolution: resolution,
      status: 'resolved',
    });
  }

  /**
   * Get alert age in minutes since creation
   */
  getAge() {
    return Math.floor((new Date() - this.created_at) / (1000 * 60));
  }

  /**
   * Get time to acknowledge in minutes
   */
  getResponseTime() {
    if (!this.acknowledged_at) return null;
    return Math.floor((this.acknowledged_at - this.created_at) / (1000 * 60));
  }

  /**
   * Get time to resolve in minutes
   */
  getResolutionTime() {
    if (!this.resolved_at) return null;
    return Math.floor((this.resolved_at - this.created_at) / (1000 * 60));
  }

  /**
   * Format alert for notifications
   */
  toNotification() {
    return {
      id: this.id,
      title: this.title,
      message: this.message,
      severity: this.severity,
      type: this.type,
      source: this.source,
      created_at: this.created_at,
      age_minutes: this.getAge(),
      metadata: this.metadata,
    };
  }
}

Alert.init({
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  
  // Identification
  title: {
    type: DataTypes.STRING(255),
    allowNull: false,
    comment: 'Short descriptive title of the alert',
  },
  message: {
    type: DataTypes.TEXT,
    allowNull: false,
    comment: 'Detailed alert message',
  },
  
  // Classification
  type: {
    type: DataTypes.ENUM(
      'security_breach',
      'firewall_rule_violation',
      'system_error',
      'performance_issue',
      'configuration_change',
      'authentication_failure',
      'network_anomaly',
      'service_failure',
      'policy_violation',
      'compliance_issue'
    ),
    allowNull: false,
    comment: 'Category/type of the alert',
  },
  severity: {
    type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
    allowNull: false,
    defaultValue: 'medium',
    comment: 'Severity level of the alert',
  },
  status: {
    type: DataTypes.ENUM('active', 'acknowledged', 'resolved', 'suppressed'),
    allowNull: false,
    defaultValue: 'active',
    comment: 'Current lifecycle status of the alert',
  },
  
  // Source information
  source: {
    type: DataTypes.STRING(100),
    allowNull: false,
    comment: 'System or component that generated the alert',
  },
  source_ip: {
    type: DataTypes.INET,
    allowNull: true,
    comment: 'Related source IP address',
  },
  source_port: {
    type: DataTypes.INTEGER,
    allowNull: true,
    validate: { min: 1, max: 65535 },
    comment: 'Related source port number',
  },
  
  // Related entities
  rule_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: { model: 'rules', key: 'id' },
    comment: 'Associated firewall rule ID',
  },
  policy_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: { model: 'policies', key: 'id' },
    comment: 'Associated policy ID',
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: { model: 'users', key: 'id' },
    comment: 'Associated user ID',
  },
  
  // Lifecycle tracking
  first_occurrence: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
    comment: 'Timestamp of the first occurrence',
  },
  last_occurrence: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
    comment: 'Timestamp of the most recent occurrence',
  },
  occurrence_count: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 1,
    comment: 'Number of times this alert has occurred',
  },
  
  // Response tracking
  acknowledged_at: { type: DataTypes.DATE, allowNull: true, comment: 'When alert was acknowledged' },
  acknowledged_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: { model: 'users', key: 'id' },
    comment: 'User who acknowledged the alert',
  },
  acknowledgment_note: { type: DataTypes.TEXT, allowNull: true, comment: 'Optional note when acknowledging' },
  resolved_at: { type: DataTypes.DATE, allowNull: true, comment: 'When alert was resolved' },
  resolved_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: { model: 'users', key: 'id' },
    comment: 'User who resolved the alert',
  },
  resolution: { type: DataTypes.TEXT, allowNull: true, comment: 'Resolution details' },
  
  // Auto-resolution
  auto_resolve: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'If true, the alert will auto-resolve after a set time',
  },
  auto_resolve_after: { type: DataTypes.INTEGER, allowNull: true, comment: 'Minutes until auto-resolution' },
  
  // Notification tracking
  notifications_sent: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    comment: 'Number of notifications sent',
  },
  last_notification_at: { type: DataTypes.DATE, allowNull: true, comment: 'Last notification timestamp' },
  
  // Suppression
  suppressed_until: { type: DataTypes.DATE, allowNull: true, comment: 'Alert suppressed until this time' },
  suppressed_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: { model: 'users', key: 'id' },
    comment: 'User who suppressed the alert',
  },
  suppression_reason: { type: DataTypes.TEXT, allowNull: true, comment: 'Reason for suppression' },
  
  // Metadata
  metadata: { type: DataTypes.JSONB, allowNull: true, comment: 'Additional alert metadata/context' },
  tags: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: true, defaultValue: [], comment: 'Tag list for categorization' },
  
  // External integrations
  external_id: { type: DataTypes.STRING(255), allowNull: true, comment: 'External system alert ID' },
  external_url: { type: DataTypes.TEXT, allowNull: true, comment: 'External system alert URL' },
}, {
  sequelize,
  modelName: 'Alert',
  tableName: 'alerts',
  timestamps: true,
  paranoid: true, // Soft delete enabled
  indexes: [
    { fields: ['status', 'severity'], name: 'idx_alerts_status_severity' },
    { fields: ['type', 'source'], name: 'idx_alerts_type_source' },
    { fields: ['created_at'], name: 'idx_alerts_created_at' },
    { fields: ['source_ip'], name: 'idx_alerts_source_ip' },
    { fields: ['rule_id'], name: 'idx_alerts_rule_id' },
    { fields: ['policy_id'], name: 'idx_alerts_policy_id' },
    { fields: ['user_id'], name: 'idx_alerts_user_id' },
    { fields: ['acknowledged_at'], name: 'idx_alerts_acknowledged_at' },
    { fields: ['resolved_at'], name: 'idx_alerts_resolved_at' },
    {
      fields: ['status', 'severity', 'created_at'],
      name: 'idx_alerts_active',
      where: { status: 'active' },
    },
    { fields: ['metadata'], using: 'gin', name: 'idx_alerts_metadata' },
    { fields: ['tags'], using: 'gin', name: 'idx_alerts_tags' },
  ],
  scopes: {
    active: { where: { status: 'active' } },
    critical: { where: { severity: 'critical' } },
    unacknowledged: { where: { acknowledged_at: null } },
    recent: {
      where: {
        created_at: {
          [sequelize.Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24h
        },
      },
    },
    byType: (type) => ({ where: { type } }),
    bySeverity: (severity) => ({ where: { severity } }),
  },
});

// Class methods
Alert.findActive = function() {
  return this.scope('active').findAll({
    order: [['severity', 'DESC'], ['created_at', 'DESC']],
  });
};

Alert.findCritical = function() {
  return this.scope(['active', 'critical']).findAll({
    order: [['created_at', 'DESC']],
  });
};

Alert.findUnacknowledged = function() {
  return this.scope(['active', 'unacknowledged']).findAll({
    order: [['severity', 'DESC'], ['created_at', 'DESC']],
  });
};

Alert.findBySourceIP = function(ip) {
  return this.findAll({
    where: { source_ip: ip },
    order: [['created_at', 'DESC']],
  });
};

Alert.getStatistics = async function() {
  const stats = await this.findAll({
    attributes: ['status', 'severity', [sequelize.fn('COUNT', '*'), 'count']],
    group: ['status', 'severity'],
    raw: true,
  });

  return stats.reduce((acc, stat) => {
    if (!acc[stat.status]) acc[stat.status] = {};
    acc[stat.status][stat.severity] = parseInt(stat.count);
    return acc;
  }, {});
};

// Associations
Alert.associate = (models) => {
  // Alert appartiene a una Rule
  if (models.Rule) {
    Alert.belongsTo(models.Rule, {
      as: 'rule',
      foreignKey: 'rule_id',
    });
  }

  // Alert appartiene a una Policy (se esiste)
  if (models.Policy) {
    Alert.belongsTo(models.Policy, {
      as: 'policy',
      foreignKey: 'policy_id',
    });
  }

  // Alert appartiene a Users per acknowledge/resolve/suppress
  if (models.User) {
    Alert.belongsTo(models.User, {
      as: 'acknowledgedBy',
      foreignKey: 'acknowledged_by',
    });
    
    Alert.belongsTo(models.User, {
      as: 'resolvedBy',
      foreignKey: 'resolved_by',
    });
    
    Alert.belongsTo(models.User, {
      as: 'suppressedBy',
      foreignKey: 'suppressed_by',
    });
  }
};

module.exports = Alert;