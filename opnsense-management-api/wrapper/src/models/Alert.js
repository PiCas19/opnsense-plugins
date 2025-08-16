const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Alert extends Model {
  /**
   * Check if alert is active
   */
  isActive() {
    return this.status === 'active' && !this.acknowledged_at;
  }

  /**
   * Check if alert is critical
   */
  isCritical() {
    return this.severity === 'critical';
  }

  /**
   * Mark alert as acknowledged
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
   * Mark alert as resolved
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
   * Get alert age in minutes
   */
  getAge() {
    return Math.floor((new Date() - this.created_at) / (1000 * 60));
  }

  /**
   * Get response time in minutes (time to acknowledge)
   */
  getResponseTime() {
    if (!this.acknowledged_at) return null;
    return Math.floor((this.acknowledged_at - this.created_at) / (1000 * 60));
  }

  /**
   * Get resolution time in minutes (time to resolve)
   */
  getResolutionTime() {
    if (!this.resolved_at) return null;
    return Math.floor((this.resolved_at - this.created_at) / (1000 * 60));
  }

  /**
   * Format alert for notification
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
  
  // Alert identification
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
  
  // Alert classification
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
    comment: 'Type/category of the alert',
  },
  
  severity: {
    type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
    allowNull: false,
    defaultValue: 'medium',
    comment: 'Alert severity level',
  },
  
  status: {
    type: DataTypes.ENUM('active', 'acknowledged', 'resolved', 'suppressed'),
    allowNull: false,
    defaultValue: 'active',
    comment: 'Current status of the alert',
  },
  
  // Source information
  source: {
    type: DataTypes.STRING(100),
    allowNull: false,
    comment: 'Source system/component that generated the alert',
  },
  
  source_ip: {
    type: DataTypes.INET,
    allowNull: true,
    comment: 'IP address related to the alert',
  },
  
  source_port: {
    type: DataTypes.INTEGER,
    allowNull: true,
    validate: {
      min: 1,
      max: 65535,
    },
    comment: 'Port number related to the alert',
  },
  
  // Related entities
  rule_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'rules',
      key: 'id',
    },
    comment: 'Related firewall rule ID',
  },
  
  policy_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'policies',
      key: 'id',
    },
    comment: 'Related policy ID',
  },
  
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'Related user ID',
  },
  
  // Alert lifecycle
  first_occurrence: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
    comment: 'First time this alert occurred',
  },
  
  last_occurrence: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
    comment: 'Last time this alert occurred',
  },
  
  occurrence_count: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 1,
    comment: 'Number of times this alert has occurred',
  },
  
  // Response tracking
  acknowledged_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the alert was acknowledged',
  },
  
  acknowledged_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who acknowledged the alert',
  },
  
  acknowledgment_note: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Note added when acknowledging the alert',
  },
  
  resolved_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the alert was resolved',
  },
  
  resolved_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who resolved the alert',
  },
  
  resolution: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Description of how the alert was resolved',
  },
  
  // Auto-resolution
  auto_resolve: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether alert should auto-resolve',
  },
  
  auto_resolve_after: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Minutes after which to auto-resolve',
  },
  
  // Notification tracking
  notifications_sent: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    comment: 'Number of notifications sent for this alert',
  },
  
  last_notification_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When last notification was sent',
  },
  
  // Suppression
  suppressed_until: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Alert is suppressed until this time',
  },
  
  suppressed_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who suppressed the alert',
  },
  
  suppression_reason: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Reason for suppressing the alert',
  },
  
  // Additional data
  metadata: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Additional alert metadata and context',
  },
  
  tags: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Tags for categorizing alerts',
  },
  
  // External system integration
  external_id: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'ID in external ticketing/monitoring system',
  },
  
  external_url: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'URL to view alert in external system',
  },
}, {
  sequelize,
  modelName: 'Alert',
  tableName: 'alerts',
  timestamps: true,
  paranoid: true, // Soft deletes
  indexes: [
    {
      fields: ['status', 'severity'],
      name: 'idx_alerts_status_severity',
    },
    {
      fields: ['type', 'source'],
      name: 'idx_alerts_type_source',
    },
    {
      fields: ['created_at'],
      name: 'idx_alerts_created_at',
    },
    {
      fields: ['source_ip'],
      name: 'idx_alerts_source_ip',
    },
    {
      fields: ['rule_id'],
      name: 'idx_alerts_rule_id',
    },
    {
      fields: ['policy_id'],
      name: 'idx_alerts_policy_id',
    },
    {
      fields: ['user_id'],
      name: 'idx_alerts_user_id',
    },
    {
      fields: ['acknowledged_at'],
      name: 'idx_alerts_acknowledged_at',
    },
    {
      fields: ['resolved_at'],
      name: 'idx_alerts_resolved_at',
    },
    {
      // Composite index for active alerts
      fields: ['status', 'severity', 'created_at'],
      name: 'idx_alerts_active',
      where: {
        status: 'active',
      },
    },
    {
      // GIN index for metadata JSONB queries
      fields: ['metadata'],
      using: 'gin',
      name: 'idx_alerts_metadata',
    },
    {
      // GIN index for tags array queries
      fields: ['tags'],
      using: 'gin',
      name: 'idx_alerts_tags',
    },
  ],
  scopes: {
    active: {
      where: {
        status: 'active',
      },
    },
    critical: {
      where: {
        severity: 'critical',
      },
    },
    unacknowledged: {
      where: {
        acknowledged_at: null,
      },
    },
    recent: {
      where: {
        created_at: {
          [sequelize.Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        },
      },
    },
    byType: (type) => ({
      where: {
        type: type,
      },
    }),
    bySeverity: (severity) => ({
      where: {
        severity: severity,
      },
    }),
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
    attributes: [
      'status',
      'severity',
      [sequelize.fn('COUNT', '*'), 'count'],
    ],
    group: ['status', 'severity'],
    raw: true,
  });

  return stats.reduce((acc, stat) => {
    if (!acc[stat.status]) acc[stat.status] = {};
    acc[stat.status][stat.severity] = parseInt(stat.count);
    return acc;
  }, {});
};

module.exports = Alert;