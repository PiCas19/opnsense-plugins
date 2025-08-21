const { DataTypes, Model, Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');
const crypto = require('crypto');

class User extends Model {
  /**
   * Hash password prima del salvataggio
   */
  async hashPassword(password) {
    try {
      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;
      const salt = bcrypt.genSaltSync(saltRounds);
      return bcrypt.hashSync(password, salt);
    } catch (error) {
      logger.error('Failed to hash password', { error: error.message });
      throw error;
    }
  }

  /**
   * Verifica password
   */
  async verifyPassword(password) {
    try {
      const isValid = bcrypt.compareSync(password, this.password);

      // Aggiorna tracking login
      if (isValid) {
        await this.update({
          last_login: new Date(),
          failed_login_attempts: 0,
        });
      } else {
        await this.increment('failed_login_attempts');
      }

      return isValid;
    } catch (error) {
      logger.error('Failed to verify password', {
        error: error.message,
        user_id: this.id,
      });
      throw error;
    }
  }

  /**
   * Controlla se l'account è bloccato
   */
  isAccountLocked() {
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5;
    const lockoutDuration = parseInt(process.env.LOCKOUT_DURATION_MINUTES, 10) || 30;

    if (this.failed_login_attempts >= maxAttempts) {
      if (this.last_failed_login) {
        const timeSinceLastFailure = Date.now() - new Date(this.last_failed_login).getTime();
        const lockoutDurationMs = lockoutDuration * 60 * 1000;
        return timeSinceLastFailure < lockoutDurationMs;
      }
      return true;
    }
    return false;
  }

  /**
   * Reset tentativi falliti
   */
  async resetFailedAttempts() {
    try {
      await this.update({
        failed_login_attempts: 0,
        last_failed_login: null,
      });
    } catch (error) {
      logger.error('Failed to reset failed attempts', {
        error: error.message,
        user_id: this.id,
      });
      throw error;
    }
  }

  /**
   * Controlla permessi utente
   */
  hasPermission(permission) {
    const rolePermissions = {
      admin: [
        'create_rules',
        'update_rules',
        'delete_rules',
        'toggle_rules',
        'apply_config',
        'manage_users',
        'view_users',
        'create_users',
        'update_users',
        'delete_users',
        'view_health',
        'view_logs'
      ],
      operator: [
        'create_rules',
        'update_rules',
        'delete_rules',
        'toggle_rules',
        'apply_config',
        'view_health'
      ],
      viewer: [
        'view_rules',
        'view_health'
      ],
    };

    return rolePermissions[this.role]?.includes(permission) || false;
  }

  /**
   * Nome display
   */
  getDisplayName() {
    if (this.first_name && this.last_name) {
      return `${this.first_name} ${this.last_name}`;
    }
    return this.username;
  }

  /**
   * Profilo completo
   */
  isProfileComplete() {
    const requiredFields = ['username', 'email', 'role'];
    return requiredFields.every((field) => this[field]);
  }

  /**
   * Aggiorna ultima attività
   */
  async updateLastActivity() {
    try {
      await this.update({ last_activity: new Date() });
    } catch (error) {
      logger.error('Failed to update last activity', {
        error: error.message,
        user_id: this.id,
      });
    }
  }

  /**
   * Ritorna dati sicuri (senza password)
   */
  toSafeJSON() {
    const values = { ...this.dataValues };
    delete values.password;
    delete values.email_verification_token;
    delete values.password_reset_token;
    return values;
  }

  /**
   * Genera token per reset password
   */
  generatePasswordResetToken() {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 ora
    
    this.password_reset_token = token;
    this.password_reset_expires = expires;
    
    return token;
  }

  /**
   * Verifica token reset password
   */
  isPasswordResetTokenValid(token) {
    return this.password_reset_token === token && 
           this.password_reset_expires && 
           this.password_reset_expires > new Date();
  }

  /**
   * Controlla se la password deve essere cambiata
   */
  shouldChangePassword() {
    if (!this.password_changed_at) return true;
    
    const passwordAge = Date.now() - new Date(this.password_changed_at).getTime();
    const maxAge = 90 * 24 * 60 * 60 * 1000; // 90 giorni
    
    return passwordAge > maxAge;
  }

  /**
   * Ottieni statistiche utente
   */
  async getStatistics() {
    const Rule = require('./Rule');
    
    const stats = {
      total_rules_created: await Rule.count({ where: { created_by: this.id } }),
      active_rules: await Rule.count({ where: { created_by: this.id, enabled: true } }),
      last_rule_created: await Rule.findOne({
        where: { created_by: this.id },
        order: [['created_at', 'DESC']],
        attributes: ['created_at', 'description']
      }),
      account_age_days: Math.floor((Date.now() - new Date(this.created_at).getTime()) / (24 * 60 * 60 * 1000))
    };

    return stats;
  }
}

// Definizione modello
User.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      allowNull: false,
    },
    username: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: { name: 'unique_username', msg: 'Username già esistente' },
      validate: {
        notEmpty: { msg: 'Username non può essere vuoto' },
        len: { args: [3, 50], msg: 'Username deve essere tra 3 e 50 caratteri' },
        is: {
          args: /^[a-zA-Z0-9_-]+$/,
          msg: 'Username può contenere solo lettere, numeri, underscore e trattini',
        },
      },
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: { name: 'unique_email', msg: 'Email già esistente' },
      validate: {
        notEmpty: { msg: 'Email non può essere vuota' },
        isEmail: { msg: 'Formato email non valido' },
      },
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        notEmpty: { msg: 'Password non può essere vuota' },
        len: { args: [8, 255], msg: 'Password deve essere almeno 8 caratteri' },
        isComplexPassword(value) {
          const hasUppercase = /[A-Z]/.test(value);
          const hasLowercase = /[a-z]/.test(value);
          const hasNumber = /\d/.test(value);
          const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(value);
          if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar) {
            throw new Error(
              'Password deve contenere almeno una maiuscola, una minuscola, un numero e un carattere speciale'
            );
          }
        },
      },
    },
    first_name: {
      type: DataTypes.STRING(50),
      allowNull: true,
      validate: {
        len: { args: [0, 50], msg: 'Nome non può superare 50 caratteri' },
      },
    },
    last_name: {
      type: DataTypes.STRING(50),
      allowNull: true,
      validate: {
        len: { args: [0, 50], msg: 'Cognome non può superare 50 caratteri' },
      },
    },
    role: {
      type: DataTypes.ENUM('admin', 'operator', 'viewer'),
      allowNull: false,
      defaultValue: 'viewer',
      validate: {
        isIn: { args: [['admin', 'operator', 'viewer']], msg: 'Ruolo non valido' },
      },
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    last_login: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    last_activity: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    failed_login_attempts: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      validate: { min: 0 },
    },
    last_failed_login: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    password_changed_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    email_verified: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
    },
    email_verification_token: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    password_reset_token: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    password_reset_expires: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    two_factor_enabled: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
    },
    two_factor_secret: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    backup_codes: {
      type: DataTypes.JSON,
      allowNull: true,
      validate: {
        isValidBackupCodes(value) {
          if (value && (!Array.isArray(value) || value.length !== 10)) {
            throw new Error('Backup codes devono essere un array di esattamente 10 codici');
          }
        },
      },
    },
    preferences: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {
        theme: 'light',
        language: 'it',
        timezone: 'Europe/Rome',
        notifications: { 
          email: true, 
          browser: true, 
          critical_only: false 
        },
      },
      validate: {
        isValidPreferences(value) {
          if (value && typeof value !== 'object') {
            throw new Error('Preferenze devono essere un oggetto JSON valido');
          }
        },
      },
    },
    login_ip: {
      type: DataTypes.STRING(45), // IPv6 compatible
      allowNull: true,
    },
    user_agent: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    api_tokens: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: [],
      comment: 'Array di token API per l\'utente'
    },
    session_data: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Dati sessione utente'
    }
  },
  {
    sequelize,
    modelName: 'User',
    tableName: 'users',
    timestamps: true,
    underscored: true,
    paranoid: true, // soft delete
    hooks: {
      beforeCreate: async (user) => {
        if (user.password) {
          user.password = await user.hashPassword(user.password);
          user.password_changed_at = new Date();
        }
        if (!user.email_verified) {
          user.email_verification_token = crypto.randomBytes(32).toString('hex');
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed('password')) {
          user.password = await user.hashPassword(user.password);
          user.password_changed_at = new Date();
          user.failed_login_attempts = 0;
          user.last_failed_login = null;
          // Invalida token reset password
          user.password_reset_token = null;
          user.password_reset_expires = null;
        }
        if (user.changed('failed_login_attempts') && user.failed_login_attempts > 0) {
          user.last_failed_login = new Date();
        }
      },
      beforeValidate: (user) => {
        if (user.email) user.email = user.email.toLowerCase().trim();
        if (user.username) user.username = user.username.toLowerCase().trim();
        if (user.first_name) user.first_name = user.first_name.trim();
        if (user.last_name) user.last_name = user.last_name.trim();
      },
      afterCreate: (user) => {
        logger.info('User created', {
          user_id: user.id,
          username: user.username,
          role: user.role
        });
      },
      afterUpdate: (user) => {
        logger.info('User updated', {
          user_id: user.id,
          username: user.username,
          changed: user.changed()
        });
      },
      beforeDestroy: (user) => {
        logger.info('User deleted', {
          user_id: user.id,
          username: user.username
        });
      }
    },
    indexes: [
      { fields: ['email'], unique: true },
      { fields: ['username'], unique: true },
      { fields: ['role'] },
      { fields: ['is_active'] },
      { fields: ['last_login'] },
      { fields: ['last_activity'] },
      { fields: ['email_verification_token'] },
      { fields: ['password_reset_token'] },
      { fields: ['failed_login_attempts'] },
      { fields: ['created_at'] },
      { fields: ['deleted_at'] }
    ],
    scopes: {
      active: { where: { is_active: true } },
      withRole: (role) => ({ where: { role } }),
      recentlyActive: {
        where: {
          last_activity: { [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
        },
      },
      needsPasswordChange: {
        where: {
          [Op.or]: [
            { password_changed_at: null },
            { 
              password_changed_at: { 
                [Op.lte]: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) 
              } 
            }
          ]
        }
      },
      locked: {
        where: {
          failed_login_attempts: { [Op.gte]: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5 }
        }
      }
    },
  }
);

// Metodi di classe
User.findByEmail = function (email) {
  return this.findOne({
    where: { email: email.toLowerCase().trim(), is_active: true },
  });
};

User.findByUsername = function (username) {
  return this.findOne({
    where: { username: username.toLowerCase().trim(), is_active: true },
  });
};

User.findActiveUsers = function () {
  return this.findAll({
    where: { is_active: true },
    order: [['created_at', 'DESC']],
  });
};

User.findByRole = function (role) {
  return this.findAll({
    where: { role, is_active: true },
    order: [['username', 'ASC']],
  });
};

User.findRecentlyActive = function (days = 30) {
  return this.scope('recentlyActive').findAll({
    order: [['last_activity', 'DESC']]
  });
};

User.findNeedingPasswordChange = function () {
  return this.scope('needsPasswordChange').findAll({
    order: [['password_changed_at', 'ASC']]
  });
};

User.findLocked = function () {
  return this.scope('locked').findAll({
    order: [['last_failed_login', 'DESC']]
  });
};

User.getStatistics = async function () {
  const total = await this.count();
  const active = await this.count({ where: { is_active: true } });
  const byRole = await this.findAll({
    attributes: [
      'role',
      [sequelize.fn('COUNT', '*'), 'count']
    ],
    group: ['role'],
    raw: true
  });
  
  const recentLogins = await this.count({
    where: {
      last_login: {
        [Op.gte]: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
      }
    }
  });

  return {
    total,
    active,
    inactive: total - active,
    recent_logins: recentLogins,
    by_role: byRole
  };
};

// Associazioni
User.associate = (models) => {
  if (models.Rule) {
    User.hasMany(models.Rule, { 
      as: 'createdRules', 
      foreignKey: 'created_by',
    });
    User.hasMany(models.Rule, { 
      as: 'updatedRules', 
      foreignKey: 'updated_by',
    });
    User.hasMany(models.Rule, { 
      as: 'reviewedRules', 
      foreignKey: 'reviewed_by',
    });
  }
};

module.exports = User;