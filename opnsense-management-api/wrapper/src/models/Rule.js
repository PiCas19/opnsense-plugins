'use strict';

const { DataTypes, Model, Op } = require('sequelize');
const { sequelize } = require('../config/database');

class Rule extends Model {
  /* ---------------------------- Instance helpers ---------------------------- */

  /** Is the rule enabled and not suspended? */
  isActive() {
    return this.enabled && !this.suspended;
  }

  /** Does the rule allow traffic? */
  isAllowRule() {
    return this.action === 'pass';
  }

  /** Does the rule block/reject traffic? */
  isBlockRule() {
    return this.action === 'block' || this.action === 'reject';
  }

  /** Priority score (bigger = earlier in evaluation when sorting by score) */
  getPriorityScore() {
    const sequenceScore = 10000 - (this.sequence || 5000);
    const actionScore =
      this.action === 'block' ? 100 :
      this.action === 'reject' ? 90 :
      this.action === 'pass' ? 50 : 0;
    return sequenceScore + actionScore;
  }

  /** Check if a traffic sample matches this rule */
  matchesTraffic(traffic) {
    const { source_ip, dest_ip, source_port, dest_port, protocol } = traffic;

    if (this.protocol !== 'any' && this.protocol !== protocol) return false;
    if (!this.matchesSource(source_ip, source_port)) return false;
    if (!this.matchesDestination(dest_ip, dest_port)) return false;

    return true;
  }

  /** Check source side */
  matchesSource(ip, port) {
    if (!this.source_config) return true;
    const src = this.source_config;

    switch (src.type) {
      case 'any': break;
      case 'single':
        if (src.address && src.address !== ip) return false;
        break;
      case 'network':
        if (src.network && !this.isIpInNetwork(ip, src.network)) return false;
        break;
      case 'alias':
        // alias resolution omitted on purpose
        break;
      default:
        return false;
    }

    if (src.port && port && !this.matchesPort(port, src.port)) return false;
    return true;
  }

  /** Check destination side */
  matchesDestination(ip, port) {
    if (!this.destination_config) return true;
    const dst = this.destination_config;

    switch (dst.type) {
      case 'any': break;
      case 'single':
        if (dst.address && dst.address !== ip) return false;
        break;
      case 'network':
        if (dst.network && !this.isIpInNetwork(ip, dst.network)) return false;
        break;
      case 'alias':
        // alias resolution omitted on purpose
        break;
      default:
        return false;
    }

    if (dst.port && port && !this.matchesPort(port, dst.port)) return false;
    return true;
  }

  /** IPv4 CIDR check */
  isIpInNetwork(ip, cidr) {
    const [network, prefixLength] = cidr.split('/');
    const ipParts = ip.split('.').map(Number);
    const netParts = network.split('.').map(Number);
    const prefix = parseInt(prefixLength, 10);

    const ipBin  = (ipParts[0]  << 24) | (ipParts[1]  << 16) | (ipParts[2]  << 8) | ipParts[3];
    const netBin = (netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3];
    const mask = (-1 << (32 - prefix)) >>> 0;

    return (ipBin & mask) === (netBin & mask);
  }

  /** Port match (single or range “start-end”) */
  matchesPort(port, rulePort) {
    if (typeof rulePort === 'number') return port === rulePort;

    if (typeof rulePort === 'string') {
      if (rulePort.includes('-')) {
        const [start, end] = rulePort.split('-').map(Number);
        return port >= start && port <= end;
      }
      return port === parseInt(rulePort, 10);
    }
    return false;
  }

  /** Update usage statistics and counters */
  async updateStatistics(action, bytes = 0, packets = 1) {
    const stats = this.statistics || {};
    const today = new Date().toISOString().split('T')[0];

    if (!stats.daily) stats.daily = {};
    if (!stats.daily[today]) {
      stats.daily[today] = { hits: 0, bytes: 0, packets: 0, blocks: 0, allows: 0 };
    }

    const daily = stats.daily[today];
    daily.hits += 1;
    daily.bytes += bytes;
    daily.packets += packets;
    if (action === 'allow') daily.allows += 1;
    if (action === 'block' || action === 'reject') daily.blocks += 1;

    stats.total_hits    = (stats.total_hits    || 0) + 1;
    stats.total_bytes   = (stats.total_bytes   || 0) + bytes;
    stats.total_packets = (stats.total_packets || 0) + packets;
    stats.last_hit = new Date();

    return await this.update({
      statistics: stats,
      last_matched_at: new Date(),
      hit_count: (this.hit_count || 0) + 1,
    });
  }

  /** Simple effectiveness score (hits/day * 10) */
  getEffectivenessScore() {
    if (!this.statistics) return 0;
    const totalHits = this.statistics.total_hits || 0;
    const days = Math.max(1, Math.floor((Date.now() - new Date(this.created_at).getTime()) / 86400000));
    return Math.round((totalHits / days) * 10);
  }

  /** Redundancy check vs another rule (simplified) */
  isRedundantWith(other) {
    return (
      this.interface === other.interface &&
      this.direction === other.direction &&
      this.protocol === other.protocol &&
      JSON.stringify(this.source_config) === JSON.stringify(other.source_config) &&
      JSON.stringify(this.destination_config) === JSON.stringify(other.destination_config)
    );
  }

  /** Export to OPNsense-ish format */
  toOpnsenseFormat() {
    return {
      description: this.description,
      interface: this.interface,
      direction: this.direction,
      ipprotocol: 'inet',
      protocol: this.protocol,
      source: this.source_config,
      destination: this.destination_config,
      disabled: !this.enabled,
      log: this.log_enabled,
      sequence: this.sequence,
    };
  }

  /** Structural validation for configs/ports/protocols */
  validateConfiguration() {
    const errors = [];

    if (this.source_config) {
      errors.push(...this.validateAddressConfig(this.source_config, 'source'));
    }
    if (this.destination_config) {
      errors.push(...this.validateAddressConfig(this.destination_config, 'destination'));
    }
    if (this.protocol === 'icmp' && (this.source_config?.port || this.destination_config?.port)) {
      errors.push('ICMP protocol cannot have port specifications');
    }
    return errors;
  }

  /** Validate a single address config object */
  validateAddressConfig(cfg, type) {
    const errors = [];
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

    if (cfg.type === 'single' && cfg.address && !ipRegex.test(cfg.address)) {
      errors.push(`Invalid ${type} IP address: ${cfg.address}`);
    }
    if (cfg.type === 'network' && cfg.network && !cidrRegex.test(cfg.network)) {
      errors.push(`Invalid ${type} network CIDR: ${cfg.network}`);
    }
    if (cfg.port) {
      const p = parseInt(cfg.port, 10);
      if (isNaN(p) || p < 1 || p > 65535) errors.push(`Invalid ${type} port: ${cfg.port}`);
    }
    return errors;
  }

  /* ------------------------------ Associations ----------------------------- */

  /**
   * Call this from your models loader after all models are defined:
   * Rule.associate(models)
   */
  static associate(models) {
    // Users who created/updated
    if (models.User) {
      this.belongsTo(models.User, {
        as: 'createdBy',
        foreignKey: 'created_by',
      });
      this.belongsTo(models.User, {
        as: 'updatedBy',
        foreignKey: 'updated_by',
      });
    }
    // Alerts referencing this rule
    if (models.Alert) {
      this.hasMany(models.Alert, {
        as: 'alerts',
        foreignKey: 'rule_id',
      });
    }
  }
}

/* ---------------------------------- Fields --------------------------------- */

Rule.init(
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },

    // Identity
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
      validate: { len: [3, 255], notEmpty: true },
    },

    // Core config
    interface: {
      type: DataTypes.STRING(20),
      allowNull: false,
      comment: 'Network interface (wan, lan, dmz, etc.)',
      validate: { isIn: [['wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4']] },
    },

    direction: {
      type: DataTypes.ENUM('in', 'out'),
      allowNull: false,
      defaultValue: 'in',
      comment: 'Traffic direction',
    },

    action: {
      type: DataTypes.ENUM('pass', 'block', 'reject'),
      allowNull: false,
      comment: 'Action to take on match',
    },

    protocol: {
      type: DataTypes.ENUM('tcp', 'udp', 'icmp', 'any'),
      allowNull: false,
      defaultValue: 'any',
      comment: 'L4 protocol',
    },

    // Address configs
    source_config: {
      type: DataTypes.JSONB,
      allowNull: false,
      comment: 'Source address configuration',
      validate: {
        isValidConfig(value) {
          if (!value || !value.type) throw new Error('Source configuration must have a type');
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
          if (!value || !value.type) throw new Error('Destination configuration must have a type');
          if (!['any', 'single', 'network', 'alias'].includes(value.type)) {
            throw new Error('Invalid destination type');
          }
        },
      },
    },

    // Status / control
    enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
    suspended: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    suspended_until: { type: DataTypes.DATE, allowNull: true },
    suspended_reason: { type: DataTypes.TEXT, allowNull: true },

    // Ordering
    sequence: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 1000,
      comment: 'Lower = higher priority',
      validate: { min: 1, max: 9999 },
    },

    // Logging
    log_enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    log_prefix: { type: DataTypes.STRING(50), allowNull: true },

    // Audit
    created_by: { type: DataTypes.INTEGER, allowNull: false, references: { model: 'users', key: 'id' } },
    updated_by: { type: DataTypes.INTEGER, allowNull: true, references: { model: 'users', key: 'id' } },

    // OPNsense sync
    opnsense_uuid: { type: DataTypes.UUID, allowNull: true },
    opnsense_sequence: { type: DataTypes.INTEGER, allowNull: true },
    last_synced_at: { type: DataTypes.DATE, allowNull: true },
    sync_status: {
      type: DataTypes.ENUM('pending', 'synced', 'failed', 'conflict'),
      allowNull: false,
      defaultValue: 'pending',
    },
    sync_error: { type: DataTypes.TEXT, allowNull: true },

    // Usage stats
    hit_count: { type: DataTypes.BIGINT, allowNull: false, defaultValue: 0 },
    first_matched_at: { type: DataTypes.DATE, allowNull: true },
    last_matched_at: { type: DataTypes.DATE, allowNull: true },
    statistics: { type: DataTypes.JSONB, allowNull: true },

    // Categorization
    category: { type: DataTypes.STRING(50), allowNull: true },
    tags: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: true, defaultValue: [] },

    // Compliance / governance
    compliance_frameworks: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: true, defaultValue: [] },
    business_justification: { type: DataTypes.TEXT, allowNull: true },
    risk_level: {
      type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
      allowNull: false,
      defaultValue: 'medium',
    },

    // Review / approval
    approval_status: {
      type: DataTypes.ENUM('draft', 'pending_review', 'approved', 'rejected'),
      allowNull: false,
      defaultValue: 'draft',
    },
    reviewed_by: { type: DataTypes.INTEGER, allowNull: true, references: { model: 'users', key: 'id' } },
    reviewed_at: { type: DataTypes.DATE, allowNull: true },
    review_comments: { type: DataTypes.TEXT, allowNull: true },

    // Expiration
    expires_at: { type: DataTypes.DATE, allowNull: true },
    auto_disable_on_expiry: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },

    // Test mode
    test_mode: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    test_until: { type: DataTypes.DATE, allowNull: true },

    // Change tracking
    version: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
    change_reason: { type: DataTypes.TEXT, allowNull: true },

    // Extra metadata
    metadata: { type: DataTypes.JSONB, allowNull: true },

    // External references
    external_id: { type: DataTypes.STRING(255), allowNull: true },
    external_source: { type: DataTypes.STRING(100), allowNull: true },
  },
  {
    sequelize,
    modelName: 'Rule',
    tableName: 'rules',
    timestamps: true,
    paranoid: true, // soft delete
    indexes: [
      { fields: ['uuid'], unique: true, name: 'idx_rules_uuid' },
      { fields: ['interface', 'direction', 'enabled'], name: 'idx_rules_interface_direction_enabled' },
      { fields: ['sequence', 'interface'], name: 'idx_rules_sequence_interface' },
      { fields: ['action', 'enabled'], name: 'idx_rules_action_enabled' },
      { fields: ['created_by'], name: 'idx_rules_created_by' },
      { fields: ['approval_status'], name: 'idx_rules_approval_status' },
      { fields: ['sync_status'], name: 'idx_rules_sync_status' },
      { fields: ['opnsense_uuid'], name: 'idx_rules_opnsense_uuid' },
      { fields: ['expires_at'], name: 'idx_rules_expires_at' },
      { fields: ['last_matched_at'], name: 'idx_rules_last_matched_at' },
      { fields: ['hit_count'], name: 'idx_rules_hit_count' },
      { fields: ['risk_level', 'enabled'], name: 'idx_rules_risk_enabled' },

      // JSONB/array GIN indexes (Postgres)
      { fields: ['source_config'], using: 'gin', name: 'idx_rules_source_config' },
      { fields: ['destination_config'], using: 'gin', name: 'idx_rules_destination_config' },
      { fields: ['statistics'], using: 'gin', name: 'idx_rules_statistics' },
      { fields: ['metadata'], using: 'gin', name: 'idx_rules_metadata' },
      { fields: ['tags'], using: 'gin', name: 'idx_rules_tags' },
      { fields: ['compliance_frameworks'], using: 'gin', name: 'idx_rules_compliance' },

      // Composite index for "active" rules
      {
        fields: ['enabled', 'suspended', 'approval_status', 'sequence'],
        name: 'idx_rules_active',
        where: {
          enabled: true,
          suspended: false,
          approval_status: 'approved',
        },
      },
    ],
    scopes: {
      active: { where: { enabled: true, suspended: false } },
      approved: { where: { approval_status: 'approved' } },
      pending: { where: { approval_status: 'pending_review' } },
      needsSync: { where: { sync_status: ['pending', 'failed'] } },
      expiring: (days = 30) => ({
        where: {
          expires_at: { [Op.lte]: new Date(Date.now() + days * 24 * 60 * 60 * 1000) },
        },
      }),
      byInterface: (iface) => ({ where: { interface: iface } }),
      byAction: (action) => ({ where: { action } }),
      highRisk: { where: { risk_level: ['high', 'critical'] } },
      unused: {
        where: {
          hit_count: 0,
          created_at: { [Op.lt]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
        },
      },
    },
  }
);

/* ----------------------------------- Hooks --------------------------------- */

Rule.beforeCreate(async (rule) => {
  const errors = rule.validateConfiguration();
  if (errors.length > 0) throw new Error(`Rule validation failed: ${errors.join(', ')}`);

  if (!rule.opnsense_uuid) rule.sync_status = 'pending';
});

Rule.beforeUpdate(async (rule) => {
  if (
    rule.changed('source_config') ||
    rule.changed('destination_config') ||
    rule.changed('action') ||
    rule.changed('protocol')
  ) {
    const errors = rule.validateConfiguration();
    if (errors.length > 0) throw new Error(`Rule validation failed: ${errors.join(', ')}`);

    rule.sync_status = 'pending';
    rule.version = (rule.version || 1) + 1;
  }

  // auto-clear suspension
  if (rule.suspended && rule.suspended_until && rule.suspended_until <= new Date()) {
    rule.suspended = false;
    rule.suspended_until = null;
    rule.suspended_reason = null;
  }

  // test mode expiry
  if (rule.test_mode && rule.test_until && rule.test_until <= new Date()) {
    rule.test_mode = false;
    rule.test_until = null;
  }
});

/* ------------------------------- Class methods ------------------------------ */

Rule.findActive = function () {
  return this.scope(['active', 'approved']).findAll({
    order: [['sequence', 'ASC'], ['created_at', 'ASC']],
  });
};

Rule.findByInterface = function (iface) {
  return this.scope(['active', 'approved', { method: ['byInterface', iface] }]).findAll({
    order: [['sequence', 'ASC']],
  });
};

Rule.findNeedingSync = function () {
  return this.scope('needsSync').findAll({ order: [['updated_at', 'ASC']] });
};

Rule.findExpiring = function (days = 30) {
  return this.scope({ method: ['expiring', days] }).findAll({ order: [['expires_at', 'ASC']] });
};

Rule.findUnused = function () {
  return this.scope('unused').findAll({ order: [['created_at', 'ASC']] });
};

Rule.findHighRisk = function () {
  return this.scope(['active', 'highRisk']).findAll({
    order: [['risk_level', 'DESC'], ['created_at', 'DESC']],
  });
};

Rule.getStatistics = async function () {
  const rows = await this.findAll({
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
  return rows;
};

Rule.findRedundant = async function () {
  const rules = await this.scope(['active', 'approved']).findAll({ order: [['sequence', 'ASC']] });
  const redundant = [];
  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      if (rules[i].isRedundantWith(rules[j])) {
        redundant.push({ rule1: rules[i], rule2: rules[j], reason: 'Identical configuration' });
      }
    }
  }
  return redundant;
};

Rule.bulkToggle = async function (ruleIds, enabled) {
  return await this.update(
    { enabled, sync_status: 'pending', updated_at: new Date() },
    { where: { id: ruleIds } }
  );
};

Rule.bulkUpdateSequence = async function (sequenceMap) {
  const tx = await sequelize.transaction();
  try {
    for (const [ruleId, sequence] of Object.entries(sequenceMap)) {
      // eslint-disable-next-line no-await-in-loop
      await this.update({ sequence, sync_status: 'pending' }, { where: { id: ruleId }, transaction: tx });
    }
    await tx.commit();
    return true;
  } catch (e) {
    await tx.rollback();
    throw e;
  }
};

Rule.checkExpiring = async function () {
  const soon = await this.findExpiring(7);
  for (const r of soon) {
    // eslint-disable-next-line no-await-in-loop
    if (r.auto_disable_on_expiry && r.expires_at <= new Date()) {
      await r.update({ enabled: false, suspended: true, suspended_reason: 'Rule expired' });
    }
  }
  return soon;
};

module.exports = Rule;