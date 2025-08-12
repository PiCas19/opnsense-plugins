const { DataTypes, Model } = require('sequelize');
const { sequelize } = require('../config/database');

class Rule extends Model {
  /**
   * Check if rule is currently active and enabled
   */
  isActive() {
    return this.enabled && !this.suspended;
  }

  /**
   * Check if rule allows traffic (pass action)
   */
  isAllowRule() {
    return this.action === 'pass';
  }

  /**
   * Check if rule blocks traffic
   */
  isBlockRule() {
    return this.action === 'block' || this.action === 'reject';
  }

  /**
   * Get rule priority score for ordering
   */
  getPriorityScore() {
    // Higher sequence = lower priority, invert for scoring
    const sequenceScore = 10000 - (this.sequence || 5000);
    const actionScore = this.action === 'block' ? 100 : 
                      this.action === 'reject' ? 90 : 
                      this.action === 'pass' ? 50 : 0;
    
    return sequenceScore + actionScore;
  }

  /**
   * Check if rule matches given traffic
   */
  matchesTraffic(traffic) {
    const { source_ip, dest_ip, source_port, dest_port, protocol } = traffic;
    
    // Check protocol
    if (this.protocol !== 'any' && this.protocol !== protocol) {
      return false;
    }
    
    // Check source
    if (!this.matchesSource(source_ip, source_port)) {
      return false;
    }
    
    // Check destination
    if (!this.matchesDestination(dest_ip, dest_port)) {
      return false;
    }
    
    return true;
  }

  /**
   * Check if source matches rule criteria
   */
  matchesSource(ip, port) {
    if (!this.source_config) return true;
    
    const source = this.source_config;
    
    // Check source type and address
    switch (source.type) {
      case 'any':
        break;
      case 'single':
        if (source.address && source.address !== ip) return false;
        break;
      case 'network':
        if (source.network && !this.isIpInNetwork(ip, source.network)) return false;
        break;
      case 'alias':
        // Would need to resolve alias - simplified for now
        break;
    }
    
    // Check source port
    if (source.port && port && !this.matchesPort(port, source.port)) {
      return false;
    }
    
    return true;
  }

  /**
   * Check if destination matches rule criteria
   */
  matchesDestination(ip, port) {
    if (!this.destination_config) return true;
    
    const dest = this.destination_config;
    
    // Check destination type and address
    switch (dest.type) {
      case 'any':
        break;
      case 'single':
        if (dest.address && dest.address !== ip) return false;
        break;
      case 'network':
        if (dest.network && !this.isIpInNetwork(ip, dest.network)) return false;
        break;
      case 'alias':
        // Would need to resolve alias - simplified for now
        break;
    }
    
    // Check destination port
    if (dest.port && port && !this.matchesPort(port, dest.port)) {
      return false;
    }
    
    return true;
  }

  /**
   * Check if IP is in network (CIDR)
   */
  isIpInNetwork(ip, cidr) {
    const [network, prefixLength] = cidr.split('/');
    const ipParts = ip.split('.').map(Number);
    const networkParts = network.split('.').map(Number);
    const prefix = parseInt(prefixLength);
    
    const ipBinary = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const networkBinary = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
    const mask = (-1 << (32 - prefix)) >>> 0;
    
    return (ipBinary & mask) === (networkBinary & mask);
  }

  /**
   * Check if port matches rule port criteria
   */
  matchesPort(port, rulePort) {
    if (typeof rulePort === 'number') {
      return port === rulePort;
    }
    
    if (typeof rulePort === 'string') {
      if (rulePort.includes('-')) {
        const [start, end] = rulePort.split('-').map(Number);
        return port >= start && port <= end;
      }
      return port === parseInt(rulePort);
    }
    
    return false;
  }

  /**
   * Update rule statistics
   */
  async updateStatistics(action, bytes = 0, packets = 1) {
    const stats = this.statistics || {};
    const today = new Date().toISOString().split('T')[0];
    
    if (!stats.daily) stats.daily = {};
    if (!stats.daily[today]) {
      stats.daily[today] = {
        hits: 0,
        bytes: 0,
        packets: 0,
        blocks: 0,
        allows: 0,
      };
    }
    
    const dailyStats = stats.daily[today];
    dailyStats.hits += 1;
    dailyStats.bytes += bytes;
    dailyStats.packets += packets;
    
    if (action === 'allow') dailyStats.allows += 1;
    if (action === 'block' || action === 'reject') dailyStats.blocks += 1;
    
    // Update totals
    stats.total_hits = (stats.total_hits || 0) + 1;
    stats.total_bytes = (stats.total_bytes || 0) + bytes;
    stats.total_packets = (stats.total_packets || 0) + packets;
    stats.last_hit = new Date();
    
    return await this.update({ 
      statistics: stats,
      last_matched_at: new Date(),
      hit_count: this.hit_count + 1,
    });
  }

  /**
   * Get rule effectiveness score
   */
  getEffectivenessScore() {
    if (!this.statistics) return 0;
    
    const totalHits = this.statistics.total_hits || 0;
    const daysSinceCreation = Math.max(1, Math.floor((new Date() - this.created_at) / (1000 * 60 * 60 * 24)));
    
    return Math.round((totalHits / daysSinceCreation) * 10); // Hits per day * 10
  }

  /**
   * Check if rule is redundant with another rule
   */
  isRedundantWith(otherRule) {
    // Simplified redundancy check
    return (
      this.interface === otherRule.interface &&
      this.direction === otherRule.direction &&
      this.protocol === otherRule.protocol &&
      JSON.stringify(this.source_config) === JSON.stringify(otherRule.source_config) &&
      JSON.stringify(this.destination_config) === JSON.stringify(otherRule.destination_config)
    );
  }

  /**
   * Export rule to OPNsense format
   */
  toOpnsenseFormat() {
    return {
      description: this.description,
      interface: this.interface,
      direction: this.direction,
      ipprotocol: 'inet', // IPv4
      protocol: this.protocol,
      source: this.source_config,
      destination: this.destination_config,
      disabled: !this.enabled,
      log: this.log_enabled,
      sequence: this.sequence,
    };
  }

  /**
   * Validate rule configuration
   */
  validateConfiguration() {
    const errors = [];
    
    // Validate source configuration
    if (this.source_config) {
      const sourceErrors = this.validateAddressConfig(this.source_config, 'source');
      errors.push(...sourceErrors);
    }
    
    // Validate destination configuration
    if (this.destination_config) {
      const destErrors = this.validateAddressConfig(this.destination_config, 'destination');
      errors.push(...destErrors);
    }
    
    // Validate port conflicts
    if (this.protocol === 'icmp' && 
        (this.source_config?.port || this.destination_config?.port)) {
      errors.push('ICMP protocol cannot have port specifications');
    }
    
    return errors;
  }

  /**
   * Validate address configuration
   */
  validateAddressConfig(config, type) {
    const errors = [];
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    
    if (config.type === 'single' && config.address) {
      if (!ipRegex.test(config.address)) {
        errors.push(`Invalid ${type} IP address: ${config.address}`);
      }
    }
    
    if (config.type === 'network' && config.network) {
      if (!cidrRegex.test(config.network)) {
        errors.push(`Invalid ${type} network CIDR: ${config.network}`);
      }
    }
    
    if (config.port) {
      const port = parseInt(config.port);
      if (isNaN(port) || port < 1 || port > 65535) {
        errors.push(`Invalid ${type} port: ${config.port}`);
      }
    }
    
    return errors;
  }
}

Rule.init({
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  
  // Rule identification
  uuid: {
    type: DataTypes.UUID,
    allowNull: false,
    unique: true,
    defaultValue: DataTypes.UUIDV4,
    comment: 'Unique identifier for the rule',
  },
  
  description: {
    type: DataTypes.STRING(255),
    allowNull: false,
    comment: 'Human-readable description of the rule',
    validate: {
      len: [3, 255],
      notEmpty: true,
    },
  },
  
  // Rule configuration
  interface: {
    type: DataTypes.STRING(20),
    allowNull: false,
    comment: 'Network interface (wan, lan, dmz, etc.)',
    validate: {
      isIn: [['wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4']],
    },
  },
  
  direction: {
    type: DataTypes.ENUM('in', 'out'),
    allowNull: false,
    defaultValue: 'in',
    comment: 'Traffic direction (in or out)',
  },
  
  action: {
    type: DataTypes.ENUM('pass', 'block', 'reject'),
    allowNull: false,
    comment: 'Action to take when rule matches',
  },
  
  protocol: {
    type: DataTypes.ENUM('tcp', 'udp', 'icmp', 'any'),
    allowNull: false,
    defaultValue: 'any',
    comment: 'Network protocol',
  },
  
  // Address configurations
  source_config: {
    type: DataTypes.JSONB,
    allowNull: false,
    comment: 'Source address configuration',
    validate: {
      isValidConfig(value) {
        if (!value || !value.type) {
          throw new Error('Source configuration must have a type');
        }
        if (!['any', 'single', 'network', 'alias'].includes(value.type)) {
          throw new Error('Invalid source type');
        }
      },
    },
  },
  
  destination_config: {
    type: DataTypes.JSONB,
    allowNull: false,
    comment: 'Destination address configuration',
    validate: {
      isValidConfig(value) {
        if (!value || !value.type) {
          throw new Error('Destination configuration must have a type');
        }
        if (!['any', 'single', 'network', 'alias'].includes(value.type)) {
          throw new Error('Invalid destination type');
        }
      },
    },
  },
  
  // Rule status and control
  enabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether the rule is currently enabled',
  },
  
  suspended: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether the rule is temporarily suspended',
  },
  
  suspended_until: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Auto-unsuspend the rule at this time',
  },
  
  suspended_reason: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Reason for suspending the rule',
  },
  
  // Rule ordering and priority
  sequence: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 1000,
    comment: 'Rule sequence/order (lower = higher priority)',
    validate: {
      min: 1,
      max: 9999,
    },
  },
  
  // Logging and monitoring
  log_enabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether to log matches for this rule',
  },
  
  log_prefix: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Prefix for log entries',
  },
  
  // Rule lifecycle
  created_by: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who created this rule',
  },
  
  updated_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who last updated this rule',
  },
  
  // OPNsense integration
  opnsense_uuid: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'UUID of corresponding rule in OPNsense',
  },
  
  opnsense_sequence: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Sequence number in OPNsense',
  },
  
  last_synced_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When rule was last synced with OPNsense',
  },
  
  sync_status: {
    type: DataTypes.ENUM('pending', 'synced', 'failed', 'conflict'),
    allowNull: false,
    defaultValue: 'pending',
    comment: 'Synchronization status with OPNsense',
  },
  
  sync_error: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Error message if sync failed',
  },
  
  // Usage statistics
  hit_count: {
    type: DataTypes.BIGINT,
    allowNull: false,
    defaultValue: 0,
    comment: 'Number of times rule has been matched',
  },
  
  first_matched_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When rule was first matched',
  },
  
  last_matched_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When rule was last matched',
  },
  
  statistics: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Detailed usage statistics',
  },
  
  // Rule categorization
  category: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Rule category for organization',
  },
  
  tags: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Tags for categorizing and searching rules',
  },
  
  // Compliance and governance
  compliance_frameworks: {
    type: DataTypes.ARRAY(DataTypes.STRING),
    allowNull: true,
    defaultValue: [],
    comment: 'Compliance frameworks this rule addresses',
  },
  
  business_justification: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Business justification for this rule',
  },
  
  risk_level: {
    type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
    allowNull: false,
    defaultValue: 'medium',
    comment: 'Risk level associated with this rule',
  },
  
  // Review and approval
  approval_status: {
    type: DataTypes.ENUM('draft', 'pending_review', 'approved', 'rejected'),
    allowNull: false,
    defaultValue: 'draft',
    comment: 'Approval status for rule changes',
  },
  
  reviewed_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    comment: 'User who reviewed this rule',
  },
  
  reviewed_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When rule was reviewed',
  },
  
  review_comments: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Comments from rule review',
  },
  
  // Rule expiration
  expires_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When rule expires and should be reviewed/removed',
  },
  
  auto_disable_on_expiry: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Automatically disable rule when it expires',
  },
  
  // Testing and validation
  test_mode: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether rule is in test mode (log only)',
  },
  
  test_until: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Test mode expires at this time',
  },
  
  // Change tracking
  version: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 1,
    comment: 'Rule version number',
  },
  
  change_reason: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Reason for the last change',
  },
  
  // Additional metadata
  metadata: {
    type: DataTypes.JSONB,
    allowNull: true,
    comment: 'Additional metadata for the rule',
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
    comment: 'Source system for externally managed rules',
  },
}, {
  sequelize,
  modelName: 'Rule',
  tableName: 'rules',
  timestamps: true,
  paranoid: true, // Soft deletes
  indexes: [
    {
      fields: ['uuid'],
      unique: true,
      name: 'idx_rules_uuid',
    },
    {
      fields: ['interface', 'direction', 'enabled'],
      name: 'idx_rules_interface_direction_enabled',
    },
    {
      fields: ['sequence', 'interface'],
      name: 'idx_rules_sequence_interface',
    },
    {
      fields: ['action', 'enabled'],
      name: 'idx_rules_action_enabled',
    },
    {
      fields: ['created_by'],
      name: 'idx_rules_created_by',
    },
    {
      fields: ['approval_status'],
      name: 'idx_rules_approval_status',
    },
    {
      fields: ['sync_status'],
      name: 'idx_rules_sync_status',
    },
    {
      fields: ['opnsense_uuid'],
      name: 'idx_rules_opnsense_uuid',
    },
    {
      fields: ['expires_at'],
      name: 'idx_rules_expires_at',
    },
    {
      fields: ['last_matched_at'],
      name: 'idx_rules_last_matched_at',
    },
    {
      fields: ['hit_count'],
      name: 'idx_rules_hit_count',
    },
    {
      fields: ['risk_level', 'enabled'],
      name: 'idx_rules_risk_enabled',
    },
    {
      // Composite index for active rules
      fields: ['enabled', 'suspended', 'approval_status', 'sequence'],
      name: 'idx_rules_active',
      where: {
        enabled: true,
        suspended: false,
        approval_status: 'approved',
      },
    },
    {
      // GIN index for JSONB queries
      fields: ['source_config'],
      using: 'gin',
      name: 'idx_rules_source_config',
    },
    {
      fields: ['destination_config'],
      using: 'gin',
      name: 'idx_rules_destination_config',
    },
    {
      fields: ['statistics'],
      using: 'gin',
      name: 'idx_rules_statistics',
    },
    {
      fields: ['metadata'],
      using: 'gin',
      name: 'idx_rules_metadata',
    },
    {
      // GIN index for array queries
      fields: ['tags'],
      using: 'gin',
      name: 'idx_rules_tags',
    },
    {
      fields: ['compliance_frameworks'],
      using: 'gin',
      name: 'idx_rules_compliance',
    },
  ],
  scopes: {
    active: {
      where: {
        enabled: true,
        suspended: false,
      },
    },
    approved: {
      where: {
        approval_status: 'approved',
      },
    },
    pending: {
      where: {
        approval_status: 'pending_review',
      },
    },
    needsSync: {
      where: {
        sync_status: ['pending', 'failed'],
      },
    },
    expiring: (days = 30) => ({
      where: {
        expires_at: {
          [sequelize.Sequelize.Op.lte]: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
        },
      },
    }),
    byInterface: (interface) => ({
      where: {
        interface: interface,
      },
    }),
    byAction: (action) => ({
      where: {
        action: action,
      },
    }),
    highRisk: {
      where: {
        risk_level: ['high', 'critical'],
      },
    },
    unused: {
      where: {
        hit_count: 0,
        created_at: {
          [sequelize.Sequelize.Op.lt]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Older than 30 days
        },
      },
    },
  },
});

// Hooks
Rule.beforeCreate(async (rule) => {
  // Validate configuration
  const errors = rule.validateConfiguration();
  if (errors.length > 0) {
    throw new Error(`Rule validation failed: ${errors.join(', ')}`);
  }
  
  // Set initial sync status
  if (!rule.opnsense_uuid) {
    rule.sync_status = 'pending';
  }
});

Rule.beforeUpdate(async (rule) => {
  // Check if rule configuration changed
  if (rule.changed('source_config') || rule.changed('destination_config') || 
      rule.changed('action') || rule.changed('protocol')) {
    
    // Validate configuration
    const errors = rule.validateConfiguration();
    if (errors.length > 0) {
      throw new Error(`Rule validation failed: ${errors.join(', ')}`);
    }
    
    // Mark as needing sync
    rule.sync_status = 'pending';
    rule.version += 1;
  }
  
  // Check suspension expiry
  if (rule.suspended && rule.suspended_until && rule.suspended_until <= new Date()) {
    rule.suspended = false;
    rule.suspended_until = null;
    rule.suspended_reason = null;
  }
  
  // Check test mode expiry
  if (rule.test_mode && rule.test_until && rule.test_until <= new Date()) {
    rule.test_mode = false;
    rule.test_until = null;
  }
});

// Class methods
Rule.findActive = function() {
  return this.scope(['active', 'approved']).findAll({
    order: [['sequence', 'ASC'], ['created_at', 'ASC']],
  });
};

Rule.findByInterface = function(interface) {
  return this.scope(['active', 'approved', { method: ['byInterface', interface] }]).findAll({
    order: [['sequence', 'ASC']],
  });
};

Rule.findNeedingSync = function() {
  return this.scope('needsSync').findAll({
    order: [['updated_at', 'ASC']],
  });
};

Rule.findExpiring = function(days = 30) {
  return this.scope({ method: ['expiring', days] }).findAll({
    order: [['expires_at', 'ASC']],
  });
};

Rule.findUnused = function() {
  return this.scope('unused').findAll({
    order: [['created_at', 'ASC']],
  });
};

Rule.findHighRisk = function() {
  return this.scope(['active', 'highRisk']).findAll({
    order: [['risk_level', 'DESC'], ['created_at', 'DESC']],
  });
};

Rule.getStatistics = async function() {
  const stats = await this.findAll({
    attributes: [
      'interface',
      'action',
      'approval_status',
      [sequelize.fn('COUNT', '*'), 'count'],
      [sequelize.fn('SUM', sequelize.col('hit_count')), 'total_hits'],
      [sequelize.fn('AVG', sequelize.col('sequence')), 'avg_sequence'],
    ],
    group: ['interface', 'action', 'approval_status'],
    raw: true,
  });

  return stats;
};

Rule.findRedundant = async function() {
  // Simplified redundant rule detection
  const rules = await this.scope(['active', 'approved']).findAll({
    order: [['sequence', 'ASC']],
  });
  
  const redundant = [];
  
  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      if (rules[i].isRedundantWith(rules[j])) {
        redundant.push({
          rule1: rules[i],
          rule2: rules[j],
          reason: 'Identical configuration',
        });
      }
    }
  }
  
  return redundant;
};

// Bulk operations
Rule.bulkToggle = async function(ruleIds, enabled) {
  return await this.update(
    { 
      enabled,
      sync_status: 'pending',
      updated_at: new Date(),
    },
    {
      where: {
        id: ruleIds,
      },
    }
  );
};

Rule.bulkUpdateSequence = async function(sequenceMap) {
  const transaction = await sequelize.transaction();
  
  try {
    for (const [ruleId, sequence] of Object.entries(sequenceMap)) {
      await this.update(
        { 
          sequence,
          sync_status: 'pending',
        },
        {
          where: { id: ruleId },
          transaction,
        }
      );
    }
    
    await transaction.commit();
    return true;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

// Check for expiring rules
Rule.checkExpiring = async function() {
  const expiringRules = await this.findExpiring(7); // Next 7 days
  
  for (const rule of expiringRules) {
    if (rule.auto_disable_on_expiry && rule.expires_at <= new Date()) {
      await rule.update({ 
        enabled: false,
        suspended: true,
        suspended_reason: 'Rule expired',
      });
    }
  }
  
  return expiringRules;
};

module.exports = Rule;