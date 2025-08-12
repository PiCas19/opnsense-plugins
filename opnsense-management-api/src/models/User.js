const { DataTypes, Model } = require('sequelize');
const bcrypt = require('bcrypt');
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');

class User extends Model {
  /**
   * Hash password before saving
   * @param {string} password - Plain text password
   * @returns {string} Hashed password
   */
  async hashPassword(password) {
    try {
      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
      return await bcrypt.hash(password, saltRounds);
    } catch (error) {
      logger.error('Failed to hash password', { error: error.message });
      throw error;
    }
  }

  /**
   * Verify password against stored hash
   * @param {string} password - Plain text password
   * @returns {boolean} True if password matches
   */
  async verifyPassword(password) {
    try {
      const isValid = await bcrypt.compare(password, this.password);
      
      // Update login tracking
      if (isValid) {
        await this.update({
          last_login: new Date(),
          failed_login_attempts: 0
        });
      } else {
        await this.increment('failed_login_attempts');
      }
      
      return isValid;
    } catch (error) {
      logger.error('Failed to verify password', { 
        error: error.message,
        user_id: this.id 
      });
      throw error;
    }
  }

  /**
   * Check if account is locked due to failed attempts
   * @returns {boolean} True if account is locked
   */
  isAccountLocked() {
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
    const lockoutDuration = parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 30;
    
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
   * Reset failed login attempts
   */
  async resetFailedAttempts() {
    try {
      await this.update({
        failed_login_attempts: 0,
        last_failed_login: null
      });
    } catch (error) {
      logger.error('Failed to reset failed attempts', {
        error: error.message,
        user_id: this.id
      });
      throw error;
    }
  }

  /**
   * Check if user has specific permission
   * @param {string} permission - Permission to check
   * @returns {boolean} True if user has permission
   */
  hasPermission(permission) {
    const rolePermissions = {
      admin: [
        'create_alerts', 'update_alerts', 'delete_alerts', 'resolve_alerts',
        'create_rules', 'update_rules', 'delete_rules',
        'create_policies', 'update_policies', 'delete_policies',
        'view_monitoring', 'export_metrics', 'manage_users'
      ],
      operator: [
        'create_alerts', 'update_alerts', 'resolve_alerts',
        'create_rules', 'update_rules',
        'create_policies', 'update_policies',
        'view_monitoring', 'export_metrics'
      ],
      viewer: [
        'view_alerts', 'view_rules', 'view_policies', 'view_monitoring'
      ]
    };

    return rolePermissions[this.role]?.includes(permission) || false;
  }

  /**
   * Get user's full name or username
   * @returns {string} Display name
   */
  getDisplayName() {
    if (this.first_name && this.last_name) {
      return `${this.first_name} ${this.last_name}`;
    }
    return this.username;
  }

  /**
   * Check if user profile is complete
   * @returns {boolean} True if profile is complete
   */
  isProfileComplete() {
    const requiredFields = ['username', 'email', 'role'];
    return requiredFields.every(field => this[field]);
  }

  /**
   * Update last activity timestamp
   */
  async updateLastActivity() {
    try {
      await this.update({
        last_activity: new Date()
      });
    } catch (error) {
      logger.error('Failed to update last activity', {
        error: error.message,
        user_id: this.id
      });
    }
  }
}

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
      unique: {
        name: 'unique_username',
        msg: 'Username already exists',
      },
      validate: {
        notEmpty: {
          msg: 'Username cannot be empty'
        },
        len: {
          args: [3, 50],
          msg: 'Username must be between 3 and 50 characters',
        },
        is: {
          args: /^[a-zA-Z0-9_-]+$/,
          msg: 'Username can only contain letters, numbers, underscores, and hyphens'
        }
      },
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: {
        name: 'unique_email',
        msg: 'Email already exists',
      },
      validate: {
        notEmpty: {
          msg: 'Email cannot be empty'
        },
        isEmail: {
          msg: 'Invalid email format'
        },
      },
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        notEmpty: {
          msg: 'Password cannot be empty'
        },
        len: {
          args: [8, 255],
          msg: 'Password must be at least 8 characters long',
        },
        isComplexPassword(value) {
          // Require at least one uppercase, one lowercase, one number, and one special character
          const hasUppercase = /[A-Z]/.test(value);
          const hasLowercase = /[a-z]/.test(value);
          const hasNumber = /\d/.test(value);
          const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(value);
          
          if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar) {
            throw new Error('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
          }
        }
      },
    },
    first_name: {
      type: DataTypes.STRING(50),
      allowNull: true,
      validate: {
        len: {
          args: [0, 50],
          msg: 'First name cannot exceed 50 characters'
        },
        isAlpha: {
          msg: 'First name can only contain letters'
        }
      }
    },
    last_name: {
      type: DataTypes.STRING(50),
      allowNull: true,
      validate: {
        len: {
          args: [0, 50],
          msg: 'Last name cannot exceed 50 characters'
        },
        isAlpha: {
          msg: 'Last name can only contain letters'
        }
      }
    },
    role: {
      type: DataTypes.ENUM('admin', 'operator', 'viewer'),
      allowNull: false,
      defaultValue: 'viewer',
      validate: {
        isIn: {
          args: [['admin', 'operator', 'viewer']],
          msg: 'Invalid role',
        },
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
      validate: {
        min: 0
      }
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
            throw new Error('Backup codes must be an array of exactly 10 codes');
          }
        }
      }
    },
    preferences: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {
        theme: 'light',
        language: 'en',
        timezone: 'UTC',
        notifications: {
          email: true,
          browser: true,
          critical_only: false
        }
      },
      validate: {
        isValidPreferences(value) {
          if (value && typeof value !== 'object') {
            throw new Error('Preferences must be a valid JSON object');
          }
        }
      }
    },
    login_ip: {
      type: DataTypes.INET,
      allowNull: true,
    },
    user_agent: {
      type: DataTypes.TEXT,
      allowNull: true,
    }
  },
  {
    sequelize,
    modelName: 'User',
    tableName: 'users',
    timestamps: true,
    underscored: true,
    paranoid: true,
    hooks: {
      beforeCreate: async (user) => {
        if (user.password) {
          user.password = await user.hashPassword(user.password);
          user.password_changed_at = new Date();
        }
        
        // Generate email verification token
        if (!user.email_verified) {
          user.email_verification_token = require('crypto')
            .randomBytes(32)
            .toString('hex');
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed('password')) {
          user.password = await user.hashPassword(user.password);
          user.password_changed_at = new Date();
          
          // Reset failed login attempts when password is changed
          user.failed_login_attempts = 0;
          user.last_failed_login = null;
        }
        
        // Track failed login attempts
        if (user.changed('failed_login_attempts') && user.failed_login_attempts > 0) {
          user.last_failed_login = new Date();
        }
      },
      beforeValidate: (user) => {
        // Normalize email to lowercase
        if (user.email) {
          user.email = user.email.toLowerCase().trim();
        }
        
        // Normalize username
        if (user.username) {
          user.username = user.username.toLowerCase().trim();
        }
        
        // Trim names
        if (user.first_name) {
          user.first_name = user.first_name.trim();
        }
        if (user.last_name) {
          user.last_name = user.last_name.trim();
        }
      }
    },
    indexes: [
      {
        fields: ['email'],
        unique: true
      },
      {
        fields: ['username'],
        unique: true
      },
      {
        fields: ['role']
      },
      {
        fields: ['is_active']
      },
      {
        fields: ['last_login']
      },
      {
        fields: ['email_verification_token']
      },
      {
        fields: ['password_reset_token']
      }
    ],
    scopes: {
      active: {
        where: { is_active: true }
      },
      withRole: (role) => ({
        where: { role }
      }),
      recentlyActive: {
        where: {
          last_activity: {
            [require('sequelize').Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days
          }
        }
      }
    }
  }
);

// Instance methods
User.prototype.toSafeJSON = function() {
  const values = { ...this.dataValues };
  delete values.password;
  delete values.two_factor_secret;
  delete values.backup_codes;
  delete values.email_verification_token;
  delete values.password_reset_token;
  return values;
};

// Class methods
User.findByEmail = function(email) {
  return this.findOne({
    where: { 
      email: email.toLowerCase().trim(),
      is_active: true 
    }
  });
};

User.findByUsername = function(username) {
  return this.findOne({
    where: { 
      username: username.toLowerCase().trim(),
      is_active: true 
    }
  });
};

User.findActiveUsers = function() {
  return this.findAll({
    where: { is_active: true },
    order: [['created_at', 'DESC']]
  });
};

User.findByRole = function(role) {
  return this.findAll({
    where: { role, is_active: true },
    order: [['username', 'ASC']]
  });
};

// Associations
User.associate = (models) => {
  // Alert associations
  User.hasMany(models.Alert, {
    as: 'acknowledgedAlerts',
    foreignKey: 'acknowledged_by',
    sourceKey: 'id',
  });
  
  User.hasMany(models.Alert, {
    as: 'resolvedAlerts',
    foreignKey: 'resolved_by',
    sourceKey: 'id',
  });
  
  User.hasMany(models.Alert, {
    as: 'suppressedAlerts',
    foreignKey: 'suppressed_by',
    sourceKey: 'id',
  });
  
  // Rule associations
  User.hasMany(models.Rule, {
    as: 'createdRules',
    foreignKey: 'created_by',
    sourceKey: 'id',
  });
  
  User.hasMany(models.Rule, {
    as: 'updatedRules',
    foreignKey: 'updated_by',
    sourceKey: 'id',
  });
  
  // Policy associations
  User.hasMany(models.Policy, {
    as: 'createdPolicies',
    foreignKey: 'created_by',
    sourceKey: 'id',
  });
  
  User.hasMany(models.Policy, {
    as: 'updatedPolicies',
    foreignKey: 'updated_by',
    sourceKey: 'id',
  });
  
  // Audit log association (if you have one)
  if (models.AuditLog) {
    User.hasMany(models.AuditLog, {
      as: 'auditLogs',
      foreignKey: 'user_id',
      sourceKey: 'id',
    });
  }
};

module.exports = User;