const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Policy extends Model {
  /**
   * Check if policy is currently active
   */
  isActive() {
    if (!this.enabled) return false;
    
    // Check schedule if enabled
    if (this.schedule?.enabled) {
      return this.isInSchedule();
    }
    
    return true;
  }

  /**
   * Check if current time is within policy schedule
   */
  isInSchedule() {
    if (!this.schedule?.enabled) return true;
    
    const now = new Date();
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'lowercase' });
    const currentTime = now.toTimeString().substring(0, 5); // HH:MM format
    
    // Check if current day is in schedule
    if (this.schedule.days && !this.schedule.days.includes(currentDay)) {
      return false;
    }
    
    // Check time window
    if (this.schedule.start_time && this.schedule.end_time) {
      return currentTime >= this.schedule.start_time && currentTime <= this.schedule.end_time;
    }
    
    return true;
  }

  /**
   * Check if policy matches given conditions
   */
  matchesConditions(requestData) {
    if (!this.conditions) return true;
    
    const { source_ip, destination_ip, protocol, port } = requestData;
    
    // Check source IPs
    if (this.conditions.source_ips?.length > 0) {
      if (!this.conditions.source_ips.includes(source_ip)) {
        return false;
      }
    }
    
    // Check destination IPs
    if (this.conditions.destination_ips?.length > 0) {
      if (!this.conditions.destination_ips.includes(destination_ip)) {
        return false;
      }
    }
    
    // Check protocols
    if (this.conditions.protocols?.length > 0) {
      if (!this.conditions.protocols.includes(protocol)) {
        return false;
      }
    }
    
    // Check ports
    if (this.conditions.ports?.length > 0) {
      if (!this.conditions.ports.includes(port)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Get policy effectiveness score
   */
  getEffectivenessScore() {
    if (!this.statistics) return 0;
    
    const { applied_count = 0, blocked_count = 0, allowed_count = 0 } = this.statistics;
    const total = applied_count || 1; // Avoid division by zero
    
    // Calculate effectiveness based on policy type
    switch (this.type) {
      case 'security':
        return Math.round((blocked_count / total) * 100);
      case 'access':
        return Math.round((allowed_count / total) * 100);
      default:
        return Math.round((applied_count / (applied_count + 1)) * 100);
    }
  }

  /**
   * Update policy statistics
   */
  async updateStatistics(action, value = 1) {
    const stats = this.statistics || {};
    
    if (!stats[`${action}_count`]) {
      stats[`${action}_count`] = 0;
    }
    
    stats[`${action}_count`] += value;
    stats.last_applied = new Date();
    
    return await this.update({ statistics: stats });
  }

  /**
   * Get next scheduled activation
   */
  getNextActivation() {
    if (!this.schedule?.enabled) return null;
    
    const now = new Date();
    const nextActivation = new Date(now);
    
    // Simple implementation - find next occurrence
    for (let i = 0; i < 7; i++) {
      const checkDate = new Date(now.getTime() + i * 24 * 60 * 60 * 1000);
      const checkDay = checkDate.toLocaleDateString('en-US', { weekday: 'lowercase' });
      
      if (this.schedule.days?.includes(checkDay)) {
        if (this.schedule.start_time) {
          const [hours, minutes] = this.schedule.start_time.split(':').map(Number);
          checkDate.setHours(hours, minutes, 0, 0);
          
          if (checkDate > now) {
            return checkDate;
          }
        }
      }
    }
    
    return null;
  }

  /**
   * Validate policy configuration
   */
  async validateConfiguration() {
    const errors = [];
    
    // Check if rules exist
    if (this.rules?.length > 0) {
      const Rule = require('./Rule');
      const existingRules = await Rule.findAll({
        where: { id: this.rules },
        attributes: ['id'],
      });
      
      if (existingRules.length !== this.rules.length) {
        errors.push('Some referenced rules do not exist');
      }
    }
    
    // Validate schedule
    if (this.schedule?.enabled) {
      if (this.schedule.start_time && this.schedule.end_time) {
        if (this.schedule.start_time >= this.schedule.end_time) {
          errors.push('Start time must be before end time');
        }
      }
      
      if (this.schedule.days?.length === 0) {
        errors.push('At least one day must be selected for scheduled policies');
      }
    }
    
    // Validate conditions
    if (this.conditions) {
      const { source_ips, destination_ips } = this.conditions;
      
      // Basic IP validation (simplified)
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      
      if (source_ips) {
        for (const ip of source_ips) {
          if (!ipRegex.test(ip)) {
            errors.push(`Invalid source IP: ${ip}`);
          }
        }
      }
      
      if (destination_ips) {
        for (const ip of destination_ips) {
          if (!ipRegex.test(ip)) {
            errors.push(`Invalid destination IP: ${ip}`);
          }
        }
      }
    }
    
    return errors;
  }

  /**
   * Export policy configuration
   */
  toExport() {
    return {
      name: this.name,
      description: this.description,
      type: this.type,
      rules: this.rules,
      priority: this.priority,
      schedule: this.schedule,
      conditions: this.conditions,
      metadata: this.metadata,
    };
  }
}

Policy.init({
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  
  // Policy identification
  name: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
    comment: 'Unique name for the policy',
    validate: {
      len: [3, 100],
      notEmpty: true,
    },
  },
  
  description: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Detailed description of the policy purpose',
  },
  
  // Policy classification
  type: {
    type: DataTypes.ENUM('security', 'access', 'qos', 'compliance', 'custom'),
    allowNull: false,
    comment: 'Type/category of the policy',
  },
  
  category: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Additional categorization for policies',
  },
  
  // Policy status and control
  enabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether the policy is currently enabled',
  },
  
  priority: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 50,
    validate: {
      min: 1,
      max: 100,
    },
    comment: 'Policy priority (1=lowest, 100=highest)',
  },
  
  // Rule associations
  rules: {
    type: DataTypes.ARRAY(DataTypes.INTEGER),
    allowNull: false,
    defaultValue: [],
    comment: 'Array of firewall rule IDs associated with this policy',
  },
  
  // Scheduling
  schedule: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Policy activation schedule',
    validate: {
      isValidSchedule(value) {
        if (value && value.enabled) {
          if (value.start_time && !/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(value.start_time)) {
            throw new Error('Invalid start_time format. Use HH:MM');
          }
          if (value.end_time && !/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(value.end_time)) {
            throw new Error('Invalid end_time format. Use HH:MM');
          }
          if (value.days && !Array.isArray(value.days)) {
            throw new Error('Days must be an array');
          }
        }
      },
    },
  },
  
  // Conditions for policy activation
  conditions: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Conditions that must be met for policy to apply',
  },
  
  // Policy lifecycle
  created_by: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who created this policy',
  },
  
  updated_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who last updated this policy',
  },
  
  // Activation tracking
  first_activated_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When policy was first activated',
  },
  
  last_activated_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When policy was last activated',
  },
  
  activation_count: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    comment: 'Number of times policy has been activated',
  },
  
  // Policy effectiveness metrics
  statistics: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Policy effectiveness and usage statistics',
  },
  
  // Compliance and governance
  compliance_frameworks: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Compliance frameworks this policy addresses',
  },
  
  approval_status: {
    type: DataTypes.ENUM('draft', 'pending_approval', 'approved', 'rejected'),
    allowNull: false,
    defaultValue: 'draft',
    comment: 'Approval status for policy changes',
  },
  
  approved_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who approved this policy',
  },
  
  approved_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When policy was approved',
  },
  
  // Versioning
  version: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 1,
    comment: 'Policy version number',
  },
  
  parent_policy_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'policies',
      key: 'id',
    },
    comment: 'Parent policy ID for versioning',
  },
  
  // Tags and metadata
  tags: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Tags for categorizing and searching policies',
  },
  
  metadata: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Additional metadata for the policy',
  },
  
  // External integrations
  external_id: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'External system identifier',
  },
  
  external_source: {
    type: DataTypes.STRING(100),
    allowNull: true,
    comment: 'Source system for externally managed policies',
  },
  
  // Policy expiration
  expires_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When policy expires and should be deactivated',
  },
  
  auto_renew: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether to automatically renew policy before expiration',
  },
  
  renewal_period: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Auto-renewal period in days',
  },
}, {
  sequelize,
  modelName: 'Policy',
  tableName: 'policies',
  timestamps: true,
  paranoid: true, // Soft deletes
  indexes: [
    {
      fields: ['name'],
      unique: true,
      name: 'idx_policies_name',
    },
    {
      fields: ['type', 'enabled'],
      name: 'idx_policies_type_enabled',
    },
    {
      fields: ['priority', 'enabled'],
      name: 'idx_policies_priority',
    },
    {
      fields: ['created_by'],
      name: 'idx_policies_created_by',
    },
    {
      fields: ['approval_status'],
      name: 'idx_policies_approval_status',
    },
    {
      fields: ['expires_at'],
      name: 'idx_policies_expires_at',
    },
    {
      fields: ['parent_policy_id', 'version'],
      name: 'idx_policies_versioning',
    },
    {
      // Composite index for active policies
      fields: ['enabled', 'approval_status', 'priority'],
      name: 'idx_policies_active',
      where: {
        enabled: true,
        approval_status: 'approved',
      },
    },
    {
      // GIN index for array queries
      fields: ['rules'],
      using: 'gin',
      name: 'idx_policies_rules',
    },
    {
      fields: ['tags'],
      using: 'gin',
      name: 'idx_policies_tags',
    },
    {
      fields: ['compliance_frameworks'],
      using: 'gin',
      name: 'idx_policies_compliance',
    },
    {
      // GIN index for JSONB queries
      fields: ['schedule'],
      using: 'gin',
      name: 'idx_policies_schedule',
    },
    {
      fields: ['conditions'],
      using: 'gin',
      name: 'idx_policies_conditions',
    },
    {
      fields: ['statistics'],
      using: 'gin',
      name: 'idx_policies_statistics',
    },
    {
      fields: ['metadata'],
      using: 'gin',
      name: 'idx_policies_metadata',
    },
  ],
  scopes: {
    active: {
      where: {
        enabled: true,
        approval_status: 'approved',
      },
    },
    approved: {
      where: {
        approval_status: 'approved',
      },
    },
    pending: {
      where: {
        approval_status: 'pending_approval',
      },
    },
    scheduled: {
      where: {
        'schedule.enabled': true,
      },
    },
    byType: (type) => ({
      where: {
        type: type,
      },
    }),
    byPriority: (minPriority) => ({
      where: {
        priority: {
          [sequelize.Sequelize.Op.gte]: minPriority,
        },
      },
    }),
    expiring: (days = 30) => ({
      where: {
        expires_at: {
          [sequelize.Sequelize.Op.lte]: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
        },
      },
    }),
  },
});

// Hooks
Policy.beforeCreate(async (policy) => {
  if (policy.enabled && !policy.first_activated_at) {
    policy.first_activated_at = new Date();
    policy.last_activated_at = new Date();
    policy.activation_count = 1;
  }
});

Policy.beforeUpdate(async (policy) => {
  if (policy.changed('enabled') && policy.enabled) {
    if (!policy.first_activated_at) {
      policy.first_activated_at = new Date();
    }
    policy.last_activated_at = new Date();
    policy.activation_count += 1;
  }
});

// Class methods
Policy.findActive = function() {
  return this.scope('active').findAll({
    order: [['priority', 'DESC'], ['created_at', 'ASC']],
  });
};

Policy.findByType = function(type) {
  return this.scope(['active', { method: ['byType', type] }]).findAll({
    order: [['priority', 'DESC']],
  });
};

Policy.findExpiring = function(days = 30) {
  return this.scope(['active', { method: ['expiring', days] }]).findAll({
    order: [['expires_at', 'ASC']],
  });
};

Policy.findByRuleId = function(ruleId) {
  return this.scope('active').findAll({
    where: {
      rules: {
        [sequelize.Sequelize.Op.contains]: [ruleId],
      },
    },
    order: [['priority', 'DESC']],
  });
};

Policy.getStatistics = async function() {
  const stats = await this.findAll({
    attributes: [
      'type',
      'approval_status',
      [sequelize.fn('COUNT', '*'), 'count'],
      [sequelize.fn('AVG', sequelize.col('priority')), 'avg_priority'],
    ],
    group: ['type', 'approval_status'],
    raw: true,
  });

  return stats.reduce((acc, stat) => {
    if (!acc[stat.type]) acc[stat.type] = {};
    acc[stat.type][stat.approval_status] = {
      count: parseInt(stat.count),
      avg_priority: parseFloat(stat.avg_priority),
    };
    return acc;
  }, {});
};

// Check for expiring policies
Policy.checkExpiring = async function() {
  const expiringPolicies = await this.findExpiring(7); // Next 7 days
  
  for (const policy of expiringPolicies) {
    if (policy.auto_renew && policy.renewal_period) {
      const newExpiration = new Date(policy.expires_at.getTime() + policy.renewal_period * 24 * 60 * 60 * 1000);
      await policy.update({ expires_at: newExpiration });
    }
  }
  
  return expiringPolicies;
};

module.exports = Policy;