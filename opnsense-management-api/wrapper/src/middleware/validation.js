const Joi = require('joi');
const logger = require('../utils/logger');

// ===============================
// SCHEMI DI VALIDAZIONE
// ===============================

// Schema per validazione login
const loginSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required()
    .messages({
      'string.alphanum': 'Username deve contenere solo caratteri alfanumerici',
      'string.min': 'Username deve essere di almeno 3 caratteri',
      'string.max': 'Username non può superare 30 caratteri',
      'any.required': 'Username è obbligatorio'
    }),
  password: Joi.string()
    .min(6)
    .required()
    .messages({
      'string.min': 'Password deve essere di almeno 6 caratteri',
      'any.required': 'Password è obbligatoria'
    })
});

// Schema per validazione regola firewall
const ruleSchema = Joi.object({
  // Campi obbligatori
  action: Joi.string()
    .valid('pass', 'block', 'reject')
    .required()
    .messages({
      'any.only': 'Azione deve essere: pass, block o reject',
      'any.required': 'Azione è obbligatoria'
    }),
  interface: Joi.string()
    .valid('wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4')
    .required()
    .messages({
      'any.only': 'Interfaccia deve essere: wan, lan, dmz, opt1, opt2, opt3 o opt4',
      'any.required': 'Interfaccia è obbligatoria'
    }),
  description: Joi.string()
    .min(3)
    .max(255)
    .required()
    .messages({
      'string.min': 'Descrizione deve essere di almeno 3 caratteri',
      'string.max': 'Descrizione non può superare 255 caratteri',
      'any.required': 'Descrizione è obbligatoria'
    }),
  
  // Campi opzionali
  protocol: Joi.string()
    .valid('tcp', 'udp', 'icmp', 'any')
    .default('any')
    .messages({
      'any.only': 'Protocollo deve essere: tcp, udp, icmp o any'
    }),
  enabled: Joi.boolean()
    .default(true),
  sequence: Joi.number()
    .integer()
    .min(1)
    .max(9999)
    .messages({
      'number.min': 'Sequenza deve essere almeno 1',
      'number.max': 'Sequenza non può superare 9999'
    }),
  direction: Joi.string()
    .valid('in', 'out')
    .default('in')
    .messages({
      'any.only': 'Direzione deve essere: in o out'
    }),
  log_enabled: Joi.boolean()
    .default(false),
  
  // Configurazioni indirizzi
  source_config: Joi.object({
    type: Joi.string()
      .valid('any', 'single', 'network')
      .required()
      .messages({
        'any.only': 'Tipo sorgente deve essere: any, single o network',
        'any.required': 'Tipo sorgente è obbligatorio'
      }),
    address: Joi.when('type', {
      is: 'single',
      then: Joi.string()
        .pattern(/^(\d{1,3}\.){3}\d{1,3}$/)
        .required()
        .messages({
          'string.pattern.base': 'Indirizzo IP non valido',
          'any.required': 'Indirizzo richiesto per tipo single'
        }),
      otherwise: Joi.forbidden()
    }),
    network: Joi.when('type', {
      is: 'network',
      then: Joi.string()
        .pattern(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/)
        .required()
        .messages({
          'string.pattern.base': 'Formato CIDR non valido (es: 192.168.1.0/24)',
          'any.required': 'Rete richiesta per tipo network'
        }),
      otherwise: Joi.forbidden()
    }),
    port: Joi.number()
      .integer()
      .min(1)
      .max(65535)
      .messages({
        'number.min': 'Porta deve essere almeno 1',
        'number.max': 'Porta non può superare 65535'
      })
  }).default({ type: 'any' }),
  
  destination_config: Joi.object({
    type: Joi.string()
      .valid('any', 'single', 'network')
      .required()
      .messages({
        'any.only': 'Tipo destinazione deve essere: any, single o network',
        'any.required': 'Tipo destinazione è obbligatorio'
      }),
    address: Joi.when('type', {
      is: 'single',
      then: Joi.string()
        .pattern(/^(\d{1,3}\.){3}\d{1,3}$/)
        .required()
        .messages({
          'string.pattern.base': 'Indirizzo IP non valido',
          'any.required': 'Indirizzo richiesto per tipo single'
        }),
      otherwise: Joi.forbidden()
    }),
    network: Joi.when('type', {
      is: 'network',
      then: Joi.string()
        .pattern(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/)
        .required()
        .messages({
          'string.pattern.base': 'Formato CIDR non valido (es: 192.168.1.0/24)',
          'any.required': 'Rete richiesta per tipo network'
        }),
      otherwise: Joi.forbidden()
    }),
    port: Joi.number()
      .integer()
      .min(1)
      .max(65535)
      .messages({
        'number.min': 'Porta deve essere almeno 1',
        'number.max': 'Porta non può superare 65535'
      })
  }).default({ type: 'any' }),
  
  // Metadati opzionali
  category: Joi.string()
    .max(50)
    .messages({
      'string.max': 'Categoria non può superare 50 caratteri'
    }),
  tags: Joi.array()
    .items(Joi.string().max(30))
    .max(10)
    .messages({
      'array.max': 'Massimo 10 tag consentiti'
    }),
  risk_level: Joi.string()
    .valid('low', 'medium', 'high', 'critical')
    .default('medium')
    .messages({
      'any.only': 'Livello rischio deve essere: low, medium, high o critical'
    }),
  business_justification: Joi.string()
    .max(1000)
    .messages({
      'string.max': 'Giustificazione business non può superare 1000 caratteri'
    }),
  expires_at: Joi.date()
    .greater('now')
    .messages({
      'date.greater': 'Data scadenza deve essere futura'
    }),
  auto_disable_on_expiry: Joi.boolean()
    .default(false)
});

// Schema per validazione utente
const userSchema = Joi.object({
  username: Joi.string()
    .min(3)
    .max(50)
    .pattern(/^[a-zA-Z0-9_-]+$/)
    .required()
    .messages({
      'string.pattern.base': 'Username può contenere solo lettere, numeri, underscore e trattini',
      'string.min': 'Username deve essere di almeno 3 caratteri',
      'string.max': 'Username non può superare 50 caratteri',
      'any.required': 'Username è obbligatorio'
    }),
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Email non valida',
      'any.required': 'Email è obbligatoria'
    }),
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`])/)
    .required()
    .messages({
      'string.min': 'Password deve essere di almeno 8 caratteri',
      'string.pattern.base': 'Password deve contenere almeno: una minuscola, una maiuscola, un numero e un carattere speciale',
      'any.required': 'Password è obbligatoria'
    }),
  first_name: Joi.string()
    .max(50)
    .allow('')
    .messages({
      'string.max': 'Nome non può superare 50 caratteri'
    }),
  last_name: Joi.string()
    .max(50)
    .allow('')
    .messages({
      'string.max': 'Cognome non può superare 50 caratteri'
    }),
  role: Joi.string()
    .valid('admin', 'operator', 'viewer')
    .default('viewer')
    .messages({
      'any.only': 'Ruolo deve essere: admin, operator o viewer'
    }),
  is_active: Joi.boolean()
    .default(true),
  preferences: Joi.object({
    theme: Joi.string()
      .valid('light', 'dark')
      .default('light'),
    language: Joi.string()
      .valid('it', 'en')
      .default('it'),
    timezone: Joi.string()
      .default('Europe/Rome'),
    notifications: Joi.object({
      email: Joi.boolean().default(true),
      browser: Joi.boolean().default(true),
      critical_only: Joi.boolean().default(false)
    })
  })
});

// Schema per aggiornamento utente
const userUpdateSchema = Joi.object({
  username: Joi.string()
    .min(3)
    .max(50)
    .pattern(/^[a-zA-Z0-9_-]+$/)
    .messages({
      'string.pattern.base': 'Username può contenere solo lettere, numeri, underscore e trattini',
      'string.min': 'Username deve essere di almeno 3 caratteri',
      'string.max': 'Username non può superare 50 caratteri'
    }),
  email: Joi.string()
    .email()
    .messages({
      'string.email': 'Email non valida'
    }),
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`])/)
    .messages({
      'string.min': 'Password deve essere di almeno 8 caratteri',
      'string.pattern.base': 'Password deve contenere almeno: una minuscola, una maiuscola, un numero e un carattere speciale'
    }),
  first_name: Joi.string()
    .max(50)
    .allow('')
    .messages({
      'string.max': 'Nome non può superare 50 caratteri'
    }),
  last_name: Joi.string()
    .max(50)
    .allow('')
    .messages({
      'string.max': 'Cognome non può superare 50 caratteri'
    }),
  role: Joi.string()
    .valid('admin', 'operator', 'viewer')
    .messages({
      'any.only': 'Ruolo deve essere: admin, operator o viewer'
    }),
  is_active: Joi.boolean(),
  preferences: Joi.object({
    theme: Joi.string().valid('light', 'dark'),
    language: Joi.string().valid('it', 'en'),
    timezone: Joi.string(),
    notifications: Joi.object({
      email: Joi.boolean(),
      browser: Joi.boolean(),
      critical_only: Joi.boolean()
    })
  })
});

// Schema per validazione UUID
const uuidSchema = Joi.string()
  .guid({ version: 'uuidv4' })
  .messages({
    'string.guid': 'UUID non valido'
  });

// Schema per query parameters di ricerca
const searchQuerySchema = Joi.object({
  search: Joi.string()
    .max(100)
    .allow('')
    .messages({
      'string.max': 'Termine di ricerca non può superare 100 caratteri'
    }),
  page: Joi.number()
    .integer()
    .min(1)
    .default(1)
    .messages({
      'number.min': 'Numero pagina deve essere almeno 1'
    }),
  limit: Joi.number()
    .integer()
    .min(1)
    .max(100)
    .default(25)
    .messages({
      'number.min': 'Limite deve essere almeno 1',
      'number.max': 'Limite non può superare 100'
    }),
  sortBy: Joi.string()
    .valid('sequence', 'description', 'action', 'interface', 'created_at', 'updated_at')
    .default('sequence')
    .messages({
      'any.only': 'Campo ordinamento non valido'
    }),
  sortOrder: Joi.string()
    .valid('asc', 'desc')
    .default('asc')
    .messages({
      'any.only': 'Direzione ordinamento deve essere: asc o desc'
    }),
  enabled: Joi.boolean(),
  action: Joi.string()
    .valid('pass', 'block', 'reject')
    .messages({
      'any.only': 'Azione deve essere: pass, block o reject'
    }),
  interface: Joi.string()
    .valid('wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4')
    .messages({
      'any.only': 'Interfaccia non valida'
    }),
  role: Joi.string()
    .valid('admin', 'operator', 'viewer')
    .messages({
      'any.only': 'Ruolo deve essere: admin, operator o viewer'
    }),
  active: Joi.boolean()
});

// Schema per operazioni batch
const batchOperationSchema = Joi.object({
  operation: Joi.string()
    .valid('enable', 'disable', 'delete')
    .required()
    .messages({
      'any.only': 'Operazione deve essere: enable, disable o delete',
      'any.required': 'Operazione è obbligatoria'
    }),
  rule_uuids: Joi.array()
    .items(uuidSchema)
    .min(1)
    .max(50)
    .required()
    .messages({
      'array.min': 'Almeno un UUID richiesto',
      'array.max': 'Massimo 50 UUID consentiti',
      'any.required': 'Lista UUID è obbligatoria'
    })
});

// ===============================
// MIDDLEWARE DI VALIDAZIONE
// ===============================

/**
 * Crea middleware di validazione generico
 */
const createValidationMiddleware = (schema, target = 'body') => {
  return (req, res, next) => {
    const data = target === 'query' ? req.query : req.body;
    const { error, value } = schema.validate(data, { 
      allowUnknown: false,
      stripUnknown: true,
      abortEarly: false
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      logger.warn('Errore validazione dati', {
        target,
        errors,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        user: req.user?.username
      });
      
      return res.status(400).json({
        success: false,
        message: `Errore di validazione ${target}`,
        errors
      });
    }
    
    // Sostituisci i dati originali con quelli validati e puliti
    if (target === 'query') {
      req.query = value;
    } else {
      req.body = value;
    }
    
    next();
  };
};

/**
 * Middleware per validazione UUID nei parametri
 */
const validateUUID = (req, res, next) => {
  const { uuid } = req.params;
  const { error } = uuidSchema.validate(uuid);
  
  if (error) {
    logger.warn('UUID non valido nei parametri', {
      uuid,
      ip: req.ip,
      user: req.user?.username
    });
    
    return res.status(400).json({
      success: false,
      message: 'UUID non valido',
      errors: [{
        field: 'uuid',
        message: 'Formato UUID non valido'
      }]
    });
  }
  
  next();
};

/**
 * Middleware per validazione multipli UUID nei parametri
 */
const validateMultipleUUIDs = (paramNames = ['uuid']) => {
  return (req, res, next) => {
    const errors = [];
    
    for (const paramName of paramNames) {
      const value = req.params[paramName];
      if (value) {
        const { error } = uuidSchema.validate(value);
        if (error) {
          errors.push({
            field: paramName,
            message: `${paramName} non è un UUID valido`
          });
        }
      }
    }
    
    if (errors.length > 0) {
      logger.warn('UUID multipli non validi nei parametri', {
        errors,
        params: req.params,
        ip: req.ip,
        user: req.user?.username
      });
      
      return res.status(400).json({
        success: false,
        message: 'Uno o più UUID non validi',
        errors
      });
    }
    
    next();
  };
};

/**
 * Validazione custom per indirizzi IP
 */
const validateIPAddress = (ip) => {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  
  return ip.split('.').every(octet => {
    const num = parseInt(octet, 10);
    return num >= 0 && num <= 255;
  });
};

/**
 * Validazione custom per notazione CIDR
 */
const validateCIDR = (cidr) => {
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
  if (!cidrRegex.test(cidr)) return false;
  
  const [ip, mask] = cidr.split('/');
  const maskNum = parseInt(mask, 10);
  
  return validateIPAddress(ip) && maskNum >= 0 && maskNum <= 32;
};

/**
 * Middleware per validazione avanzata regole firewall
 */
const validateAdvancedRule = (req, res, next) => {
  const { source_config, destination_config } = req.body;
  const errors = [];
  
  // Validazione source_config
  if (source_config) {
    if (source_config.type === 'single' && source_config.address) {
      if (!validateIPAddress(source_config.address)) {
        errors.push({
          field: 'source_config.address',
          message: 'Indirizzo IP sorgente non valido'
        });
      }
    }
    
    if (source_config.type === 'network' && source_config.network) {
      if (!validateCIDR(source_config.network)) {
        errors.push({
          field: 'source_config.network',
          message: 'Formato CIDR sorgente non valido'
        });
      }
    }
  }
  
  // Validazione destination_config
  if (destination_config) {
    if (destination_config.type === 'single' && destination_config.address) {
      if (!validateIPAddress(destination_config.address)) {
        errors.push({
          field: 'destination_config.address',
          message: 'Indirizzo IP destinazione non valido'
        });
      }
    }
    
    if (destination_config.type === 'network' && destination_config.network) {
      if (!validateCIDR(destination_config.network)) {
        errors.push({
          field: 'destination_config.network',
          message: 'Formato CIDR destinazione non valido'
        });
      }
    }
  }
  
  if (errors.length > 0) {
    logger.warn('Errore validazione avanzata regola', {
      errors,
      ip: req.ip,
      user: req.user?.username
    });
    
    return res.status(400).json({
      success: false,
      message: 'Errore di validazione configurazione indirizzi',
      errors
    });
  }
  
  next();
};

/**
 * Middleware per validazione conflitti regole
 */
const validateRuleConflicts = async (req, res, next) => {
  try {
    const { interface: iface, source_config, destination_config, protocol, action } = req.body;
    const Rule = require('../models/Rule');
    
    // Cerca regole potenzialmente in conflitto
    const existingRules = await Rule.findAll({
      where: {
        interface: iface,
        enabled: true
      }
    });
    
    const warnings = [];
    
    for (const rule of existingRules) {
      // Skip se stiamo aggiornando la stessa regola
      if (req.params.uuid && rule.uuid === req.params.uuid) {
        continue;
      }
      
      // Controlla sovrapposizione semplice
      if (rule.action !== action &&
          JSON.stringify(rule.source_config) === JSON.stringify(source_config) &&
          JSON.stringify(rule.destination_config) === JSON.stringify(destination_config) &&
          rule.protocol === protocol) {
        warnings.push({
          type: 'conflict',
          message: `Possibile conflitto con regola esistente: ${rule.description}`,
          conflicting_rule: rule.uuid
        });
      }
    }
    
    // Aggiungi warnings alla request per uso successivo
    req.validationWarnings = warnings;
    
    next();
  } catch (error) {
    logger.error('Errore nella validazione conflitti regole', {
      error: error.message,
      user: req.user?.username
    });
    next(); // Continua anche se la validazione conflitti fallisce
  }
};

/**
 * Middleware per sanitizzazione input
 */
const sanitizeInput = (req, res, next) => {
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str
      .trim()
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Rimuovi script
      .replace(/javascript:/gi, '') // Rimuovi javascript:
      .replace(/on\w+\s*=/gi, ''); // Rimuovi event handlers
  };
  
  const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) {
      return typeof obj === 'string' ? sanitizeString(obj) : obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    }
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value);
    }
    return sanitized;
  };
  
  // Sanitizza body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  
  // Sanitizza query
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  
  next();
};

// ===============================
// MIDDLEWARE COMBINATI
// ===============================

// Middleware per validazione login
const validateLogin = createValidationMiddleware(loginSchema);

// Middleware per validazione regola completa
const validateRule = [
  createValidationMiddleware(ruleSchema),
  validateAdvancedRule,
  validateRuleConflicts
];

// Middleware per validazione utente
const validateUser = createValidationMiddleware(userSchema);

// Middleware per validazione aggiornamento utente
const validateUserUpdate = createValidationMiddleware(userUpdateSchema);

// Middleware per validazione query di ricerca
const validateSearchQuery = createValidationMiddleware(searchQuerySchema, 'query');

// Middleware per validazione operazioni batch
const validateBatchOperation = createValidationMiddleware(batchOperationSchema);

// ===============================
// UTILITY DI VALIDAZIONE
// ===============================

/**
 * Valida array di UUID
 */
const validateUUIDs = (uuids) => {
  if (!Array.isArray(uuids)) return false;
  return uuids.every(uuid => !uuidSchema.validate(uuid).error);
};

/**
 * Valida range di porte
 */
const validatePortRange = (range) => {
  if (typeof range === 'number') {
    return range >= 1 && range <= 65535;
  }
  
  if (typeof range === 'string') {
    const parts = range.split('-');
    if (parts.length === 2) {
      const start = parseInt(parts[0], 10);
      const end = parseInt(parts[1], 10);
      return start >= 1 && end <= 65535 && start <= end;
    }
  }
  
  return false;
};

/**
 * Valida configurazione interfaccia
 */
const validateInterfaceConfig = (config) => {
  const validInterfaces = ['wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4'];
  return validInterfaces.includes(config);
};

/**
 * Middleware per logging validazione
 */
const logValidation = (req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const isValidationError = res.statusCode === 400;
    
    if (isValidationError) {
      logger.info('Validazione completata con errori', {
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        duration,
        user: req.user?.username,
        ip: req.ip
      });
    }
  });
  
  next();
};

module.exports = {
  // Middleware principali
  validateLogin,
  validateRule,
  validateUser,
  validateUserUpdate,
  validateUUID,
  validateSearchQuery,
  validateBatchOperation,
  
  // Middleware avanzati
  validateAdvancedRule,
  validateRuleConflicts,
  validateMultipleUUIDs,
  sanitizeInput,
  logValidation,
  
  // Utility
  validateUUIDs,
  validateIPAddress,
  validateCIDR,
  validatePortRange,
  validateInterfaceConfig,
  
  // Schemi (per uso esterno)
  schemas: {
    loginSchema,
    ruleSchema,
    userSchema,
    userUpdateSchema,
    uuidSchema,
    searchQuerySchema,
    batchOperationSchema
  }
};