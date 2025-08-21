const { DataTypes, Model, Op } = require('sequelize');
const { sequelize } = require('../config/database');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

class Rule extends Model {
  /**
   * Controlla se la regola è attiva
   */
  isActive() {
    return this.enabled && !this.suspended;
  }

  /**
   * Controlla se è una regola di permesso
   */
  isAllowRule() {
    return this.action === 'pass';
  }

  /**
   * Controlla se è una regola di blocco
   */
  isBlockRule() {
    return this.action === 'block' || this.action === 'reject';
  }

  /**
   * Calcola punteggio priorità
   */
  getPriorityScore() {
    const sequenceScore = 10000 - (this.sequence || 5000);
    const actionScore =
      this.action === 'block' ? 100 :
      this.action === 'reject' ? 90 :
      this.action === 'pass' ? 50 : 0;
    return sequenceScore + actionScore;
  }

  /**
   * Controlla se il traffico corrisponde a questa regola
   */
  matchesTraffic(traffic) {
    const { source_ip, dest_ip, source_port, dest_port, protocol } = traffic;

    if (this.protocol !== 'any' && this.protocol !== protocol) return false;
    if (!this.matchesSource(source_ip, source_port)) return false;
    if (!this.matchesDestination(dest_ip, dest_port)) return false;

    return true;
  }

  /**
   * Controlla corrispondenza sorgente
   */
  matchesSource(ip, port) {
    if (!this.source_config) return true;
    const src = this.source_config;

    switch (src.type) {
      case 'any': 
        break;
      case 'single':
        if (src.address && src.address !== ip) return false;
        break;
      case 'network':
        if (src.network && !this.isIpInNetwork(ip, src.network)) return false;
        break;
      default:
        return false;
    }

    if (src.port && port && !this.matchesPort(port, src.port)) return false;
    return true;
  }

  /**
   * Controlla corrispondenza destinazione
   */
  matchesDestination(ip, port) {
    if (!this.destination_config) return true;
    const dst = this.destination_config;

    switch (dst.type) {
      case 'any': 
        break;
      case 'single':
        if (dst.address && dst.address !== ip) return false;
        break;
      case 'network':
        if (dst.network && !this.isIpInNetwork(ip, dst.network)) return false;
        break;
      default:
        return false;
    }

    if (dst.port && port && !this.matchesPort(port, dst.port)) return false;
    return true;
  }

  /**
   * Verifica IPv4 CIDR
   */
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

  /**
   * Verifica corrispondenza porta
   */
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

  /**
   * Aggiorna statistiche utilizzo
   */
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

    stats.total_hits = (stats.total_hits || 0) + 1;
    stats.total_bytes = (stats.total_bytes || 0) + bytes;
    stats.total_packets = (stats.total_packets || 0) + packets;
    stats.last_hit = new Date();

    return await this.update({
      statistics: stats,
      last_matched_at: new Date(),
      hit_count: (this.hit_count || 0) + 1,
    });
  }

  /**
   * Calcola punteggio efficacia
   */
  getEffectivenessScore() {
    if (!this.statistics) return 0;
    const totalHits = this.statistics.total_hits || 0;
    const days = Math.max(1, Math.floor((Date.now() - new Date(this.created_at).getTime()) / 86400000));
    return Math.round((totalHits / days) * 10);
  }

  /**
   * Controlla ridondanza con altra regola
   */
  isRedundantWith(other) {
    return (
      this.interface === other.interface &&
      this.direction === other.direction &&
      this.protocol === other.protocol &&
      JSON.stringify(this.source_config) === JSON.stringify(other.source_config) &&
      JSON.stringify(this.destination_config) === JSON.stringify(other.destination_config)
    );
  }

  /**
   * Esporta in formato OPNsense
   */
  toOpnsenseFormat() {
    return {
      description: this.description,
      interface: this.interface,
      direction: this.direction,
      ipprotocol: 'inet',
      protocol: this.protocol,
      type: this.action,
      source_net: this.formatAddressForOPNsense(this.source_config),
      destination_net: this.formatAddressForOPNsense(this.destination_config),
      source_port: this.source_config?.port || '',
      destination_port: this.destination_config?.port || '',
      enabled: this.enabled ? '1' : '0',
      log: this.log_enabled ? '1' : '0',
      sequence: this.sequence,
      quick: '1',
      floating: '0'
    };
  }

  /**
   * Formatta indirizzo per OPNsense
   */
  formatAddressForOPNsense(config) {
    if (!config) return 'any';
    
    switch (config.type) {
      case 'any':
        return 'any';
      case 'single':
        return config.address || 'any';
      case 'network':
        return config.network || 'any';
      default:
        return 'any';
    }
  }

  /**
   * Validazione configurazione
   */
  validateConfiguration() {
    const errors = [];

    if (this.source_config) {
      errors.push(...this.validateAddressConfig(this.source_config, 'source'));
    }
    if (this.destination_config) {
      errors.push(...this.validateAddressConfig(this.destination_config, 'destination'));
    }
    if (this.protocol === 'icmp' && (this.source_config?.port || this.destination_config?.port)) {
      errors.push('Il protocollo ICMP non può avere specifiche di porta');
    }
    return errors;
  }

  /**
   * Valida configurazione indirizzo
   */
  validateAddressConfig(cfg, type) {
    const errors = [];
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

    if (cfg.type === 'single' && cfg.address && !ipRegex.test(cfg.address)) {
      errors.push(`Indirizzo IP ${type} non valido: ${cfg.address}`);
    }
    if (cfg.type === 'network' && cfg.network && !cidrRegex.test(cfg.network)) {
      errors.push(`CIDR ${type} non valido: ${cfg.network}`);
    }
    if (cfg.port) {
      const p = parseInt(cfg.port, 10);
      if (isNaN(p) || p < 1 || p > 65535) errors.push(`Porta ${type} non valida: ${cfg.port}`);
    }
    return errors;
  }

  /**
   * Conversione per API JSON
   */
  toJSON() {
    const values = { ...this.dataValues };
    
    // Formatta configurazioni per output API
    if (values.source_config) {
      values.source = this.formatAddressForOutput(values.source_config);
    }
    if (values.destination_config) {
      values.destination = this.formatAddressForOutput(values.destination_config);
    }

    return values;
  }

  /**
   * Formatta indirizzo per output
   */
  formatAddressForOutput(config) {
    if (!config) return 'any';
    
    switch (config.type) {
      case 'any':
        return 'any';
      case 'single':
        return config.address || 'any';
      case 'network':
        return config.network || 'any';
      default:
        return 'any';
    }
  }

  /**
   * Controlla se la regola è scaduta
   */
  isExpired() {
    return this.expires_at && this.expires_at <= new Date();
  }

  /**
   * Ottieni storico modifiche
   */
  async getChangeHistory() {
    // Implementazione futura per audit trail
    return {
      version: this.version,
      last_change: this.updated_at,
      change_reason: this.change_reason
    };
  }

  /**
   * Clona regola
   */
  async cloneRule(newDescription) {
    const clonedData = {
      ...this.toJSON(),
      description: newDescription || `${this.description} (Copy)`,
      uuid: uuidv4(),
      opnsense_uuid: null,
      sync_status: 'pending',
      version: 1,
      hit_count: 0,
      statistics: null,
      first_matched_at: null,
      last_matched_at: null
    };

    delete clonedData.id;
    delete clonedData.created_at;
    delete clonedData.updated_at;
    delete clonedData.deleted_at;

    return await this.constructor.create(clonedData);
  }
}

// Definizione modello
Rule.init(
  {
    id: { 
      type: DataTypes.INTEGER, 
      primaryKey: true, 
      autoIncrement: true 
    },

    // Identificatori
    uuid: {
      type: DataTypes.UUID,
      allowNull: false,
      unique: true,
      defaultValue: () => uuidv4(),
      comment: 'Identificatore unico della regola',
    },

    description: {
      type: DataTypes.STRING(255),
      allowNull: false,
     comment: 'Descrizione leggibile della regola',
     validate: { 
       len: [3, 255], 
       notEmpty: true 
     },
   },

   // Configurazione core
   interface: {
     type: DataTypes.STRING(20),
     allowNull: false,
     comment: 'Interfaccia di rete (wan, lan, dmz, ecc.)',
     validate: { 
       isIn: [['wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4']] 
     },
   },

   direction: {
     type: DataTypes.ENUM('in', 'out'),
     allowNull: false,
     defaultValue: 'in',
     comment: 'Direzione del traffico',
   },

   action: {
     type: DataTypes.ENUM('pass', 'block', 'reject'),
     allowNull: false,
     comment: 'Azione da intraprendere',
   },

   protocol: {
     type: DataTypes.ENUM('tcp', 'udp', 'icmp', 'any'),
     allowNull: false,
     defaultValue: 'any',
     comment: 'Protocollo L4',
   },

   // Configurazioni indirizzi (semplificate)
   source_config: {
     type: DataTypes.JSON,
     allowNull: false,
     defaultValue: { type: 'any' },
     comment: 'Configurazione indirizzo sorgente',
     validate: {
       isValidConfig(value) {
         if (!value || !value.type) throw new Error('La configurazione sorgente deve avere un tipo');
         if (!['any', 'single', 'network'].includes(value.type)) {
           throw new Error('Tipo sorgente non valido');
         }
       },
     },
   },

   destination_config: {
     type: DataTypes.JSON,
     allowNull: false,
     defaultValue: { type: 'any' },
     comment: 'Configurazione indirizzo destinazione',
     validate: {
       isValidConfig(value) {
         if (!value || !value.type) throw new Error('La configurazione destinazione deve avere un tipo');
         if (!['any', 'single', 'network'].includes(value.type)) {
           throw new Error('Tipo destinazione non valido');
         }
       },
     },
   },

   // Stato e controllo
   enabled: { 
     type: DataTypes.BOOLEAN, 
     allowNull: false, 
     defaultValue: true 
   },
   suspended: { 
     type: DataTypes.BOOLEAN, 
     allowNull: false, 
     defaultValue: false 
   },
   suspended_until: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },
   suspended_reason: { 
     type: DataTypes.TEXT, 
     allowNull: true 
   },

   // Ordinamento
   sequence: {
     type: DataTypes.INTEGER,
     allowNull: false,
     defaultValue: 1000,
     comment: 'Priorità (più basso = più alta priorità)',
     validate: { min: 1, max: 9999 },
   },

   // Logging
   log_enabled: { 
     type: DataTypes.BOOLEAN, 
     allowNull: false, 
     defaultValue: false 
   },
   log_prefix: { 
     type: DataTypes.STRING(50), 
     allowNull: true 
   },

   // Audit
   created_by: { 
     type: DataTypes.INTEGER, 
     allowNull: false, 
     references: { model: 'users', key: 'id' } 
   },
   updated_by: { 
     type: DataTypes.INTEGER, 
     allowNull: true, 
     references: { model: 'users', key: 'id' } 
   },

   // Sincronizzazione OPNsense
   opnsense_uuid: { 
     type: DataTypes.UUID, 
     allowNull: true 
   },
   opnsense_sequence: { 
     type: DataTypes.INTEGER, 
     allowNull: true 
   },
   last_synced_at: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },
   sync_status: {
     type: DataTypes.ENUM('pending', 'synced', 'failed', 'conflict'),
     allowNull: false,
     defaultValue: 'pending',
   },
   sync_error: { 
     type: DataTypes.TEXT, 
     allowNull: true 
   },

   // Statistiche utilizzo
   hit_count: { 
     type: DataTypes.BIGINT, 
     allowNull: false, 
     defaultValue: 0 
   },
   first_matched_at: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },
   last_matched_at: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },
   statistics: { 
     type: DataTypes.JSON, 
     allowNull: true 
   },

   // Categorizzazione
   category: { 
     type: DataTypes.STRING(50), 
     allowNull: true 
   },
   tags: { 
     type: DataTypes.JSON, 
     allowNull: true, 
     defaultValue: [] 
   },

   // Compliance
   risk_level: {
     type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
     allowNull: false,
     defaultValue: 'medium',
   },
   business_justification: { 
     type: DataTypes.TEXT, 
     allowNull: true 
   },

   // Approvazione
   approval_status: {
     type: DataTypes.ENUM('draft', 'pending_review', 'approved', 'rejected'),
     allowNull: false,
     defaultValue: 'approved', // Semplificato per questa API
   },
   reviewed_by: { 
     type: DataTypes.INTEGER, 
     allowNull: true, 
     references: { model: 'users', key: 'id' } 
   },
   reviewed_at: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },
   review_comments: { 
     type: DataTypes.TEXT, 
     allowNull: true 
   },

   // Scadenza
   expires_at: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },
   auto_disable_on_expiry: { 
     type: DataTypes.BOOLEAN, 
     allowNull: false, 
     defaultValue: false 
   },

   // Test mode
   test_mode: { 
     type: DataTypes.BOOLEAN, 
     allowNull: false, 
     defaultValue: false 
   },
   test_until: { 
     type: DataTypes.DATE, 
     allowNull: true 
   },

   // Versioning
   version: { 
     type: DataTypes.INTEGER, 
     allowNull: false, 
     defaultValue: 1 
   },
   change_reason: { 
     type: DataTypes.TEXT, 
     allowNull: true 
   },

   // Metadati extra
   metadata: { 
     type: DataTypes.JSON, 
     allowNull: true 
   },

   // Riferimenti esterni
   external_id: { 
     type: DataTypes.STRING(255), 
     allowNull: true 
   },
   external_source: { 
     type: DataTypes.STRING(100), 
     allowNull: true 
   },

   // Compliance frameworks
   compliance_frameworks: { 
     type: DataTypes.JSON, 
     allowNull: true, 
     defaultValue: [] 
   },
 },
 {
   sequelize,
   modelName: 'Rule',
   tableName: 'rules',
   timestamps: true,
   underscored: true,
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
     { fields: ['category'], name: 'idx_rules_category' },
     { fields: ['test_mode'], name: 'idx_rules_test_mode' },
     { fields: ['created_at'] },
     { fields: ['updated_at'] },
     { fields: ['deleted_at'] }
   ],
   hooks: {
     beforeCreate: async (rule) => {
       const errors = rule.validateConfiguration();
       if (errors.length > 0) throw new Error(`Validazione regola fallita: ${errors.join(', ')}`);

       if (!rule.opnsense_uuid) rule.sync_status = 'pending';
       
       logger.info('Creating rule', {
         description: rule.description,
         action: rule.action,
         interface: rule.interface
       });
     },
     beforeUpdate: async (rule) => {
       if (
         rule.changed('source_config') ||
         rule.changed('destination_config') ||
         rule.changed('action') ||
         rule.changed('protocol')
       ) {
         const errors = rule.validateConfiguration();
         if (errors.length > 0) throw new Error(`Validazione regola fallita: ${errors.join(', ')}`);

         rule.sync_status = 'pending';
         rule.version = (rule.version || 1) + 1;
       }

       // Auto-clear suspension
       if (rule.suspended && rule.suspended_until && rule.suspended_until <= new Date()) {
         rule.suspended = false;
         rule.suspended_until = null;
         rule.suspended_reason = null;
       }

       // Auto-disable expired rules
       if (rule.auto_disable_on_expiry && rule.isExpired()) {
         rule.enabled = false;
         rule.suspended = true;
         rule.suspended_reason = 'Regola scaduta automaticamente';
       }

       // Test mode expiry
       if (rule.test_mode && rule.test_until && rule.test_until <= new Date()) {
         rule.test_mode = false;
         rule.test_until = null;
       }
     },
     afterCreate: (rule) => {
       logger.info('Rule created', {
         rule_id: rule.id,
         uuid: rule.uuid,
         description: rule.description,
         created_by: rule.created_by
       });
     },
     afterUpdate: (rule) => {
       logger.info('Rule updated', {
         rule_id: rule.id,
         uuid: rule.uuid,
         description: rule.description,
         version: rule.version,
         changed: rule.changed()
       });
     },
     beforeDestroy: (rule) => {
       logger.info('Rule deleted', {
         rule_id: rule.id,
         uuid: rule.uuid,
         description: rule.description
       });
     }
   },
   scopes: {
     active: { where: { enabled: true, suspended: false } },
     approved: { where: { approval_status: 'approved' } },
     pending: { where: { approval_status: 'pending_review' } },
     needsSync: { where: { sync_status: ['pending', 'failed'] } },
     synced: { where: { sync_status: 'synced' } },
     expiring: (days = 30) => ({
       where: {
         expires_at: { [Op.lte]: new Date(Date.now() + days * 24 * 60 * 60 * 1000) },
       },
     }),
     expired: {
       where: {
         expires_at: { [Op.lte]: new Date() }
       }
     },
     byInterface: (iface) => ({ where: { interface: iface } }),
     byAction: (action) => ({ where: { action } }),
     byCategory: (category) => ({ where: { category } }),
     highRisk: { where: { risk_level: ['high', 'critical'] } },
     unused: {
       where: {
         hit_count: 0,
         created_at: { [Op.lt]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
       },
     },
     testMode: { where: { test_mode: true } },
     recentlyHit: {
       where: {
         last_matched_at: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) }
       }
     }
   },
 }
);

// Metodi di classe
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

Rule.findExpired = function () {
 return this.scope('expired').findAll({ order: [['expires_at', 'ASC']] });
};

Rule.findUnused = function () {
 return this.scope('unused').findAll({ order: [['created_at', 'ASC']] });
};

Rule.findHighRisk = function () {
 return this.scope(['active', 'highRisk']).findAll({
   order: [['risk_level', 'DESC'], ['created_at', 'DESC']],
 });
};

Rule.findByCategory = function (category) {
 return this.scope({ method: ['byCategory', category] }).findAll({
   order: [['sequence', 'ASC']]
 });
};

Rule.findRecentlyHit = function () {
 return this.scope('recentlyHit').findAll({
   order: [['last_matched_at', 'DESC']]
 });
};

Rule.findInTestMode = function () {
 return this.scope('testMode').findAll({
   order: [['test_until', 'ASC']]
 });
};

Rule.getStatistics = async function () {
 const rows = await this.findAll({
   attributes: [
     'interface',
     'action',
     'approval_status',
     'enabled',
     [sequelize.fn('COUNT', '*'), 'count'],
     [sequelize.fn('SUM', sequelize.col('hit_count')), 'total_hits'],
     [sequelize.fn('AVG', sequelize.col('sequence')), 'avg_sequence'],
   ],
   group: ['interface', 'action', 'approval_status', 'enabled'],
   raw: true,
 });
 return rows;
};

Rule.findRedundant = async function () {
 const rules = await this.scope(['active', 'approved']).findAll({ 
   order: [['sequence', 'ASC']] 
 });
 
 const redundant = [];
 for (let i = 0; i < rules.length; i++) {
   for (let j = i + 1; j < rules.length; j++) {
     if (rules[i].isRedundantWith(rules[j])) {
       redundant.push({ 
         rule1: rules[i], 
         rule2: rules[j], 
         reason: 'Configurazione identica' 
       });
     }
   }
 }
 return redundant;
};

Rule.bulkToggle = async function (ruleIds, enabled) {
 return await this.update(
   { 
     enabled, 
     sync_status: 'pending', 
     updated_at: new Date(),
     version: sequelize.literal('version + 1')
   },
   { where: { id: ruleIds } }
 );
};

Rule.bulkUpdateSequence = async function (sequenceMap) {
 const tx = await sequelize.transaction();
 try {
   for (const [ruleId, sequence] of Object.entries(sequenceMap)) {
     await this.update(
       { 
         sequence, 
         sync_status: 'pending',
         version: sequelize.literal('version + 1')
       }, 
       { where: { id: ruleId }, transaction: tx }
     );
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
   if (r.auto_disable_on_expiry && r.expires_at <= new Date()) {
     await r.update({ 
       enabled: false, 
       suspended: true, 
       suspended_reason: 'Regola scaduta automaticamente',
       sync_status: 'pending'
     });
   }
 }
 return soon;
};

Rule.prototype.syncToOPNsense = async function() {
 const OpnsenseService = require('../services/OpnsenseService');
 
 try {
   if (this.opnsense_uuid) {
     // Update existing rule
     await OpnsenseService.updateRule(this.opnsense_uuid, this.toOpnsenseFormat());
   } else {
     // Create new rule
     const result = await OpnsenseService.createRule(this.toOpnsenseFormat());
     this.opnsense_uuid = result.uuid;
   }
   
   await this.update({
     sync_status: 'synced',
     last_synced_at: new Date(),
     sync_error: null
   });
   
   return true;
 } catch (error) {
   await this.update({
     sync_status: 'failed',
     sync_error: error.message
   });
   throw error;
 }
};

// Associazioni
Rule.associate = (models) => {
 if (models.User) {
   Rule.belongsTo(models.User, {
     as: 'createdBy',
     foreignKey: 'created_by',
   });
   Rule.belongsTo(models.User, {
     as: 'updatedBy',
     foreignKey: 'updated_by',
   });
   Rule.belongsTo(models.User, {
     as: 'reviewedBy',
     foreignKey: 'reviewed_by',
   });
 }
};

module.exports = Rule;