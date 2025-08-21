const Joi = require('joi');

// Schema per validazione login
const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(6).required()
});

// Schema per validazione regola firewall
const ruleSchema = Joi.object({
  // Campi obbligatori
  action: Joi.string().valid('pass', 'block', 'reject').required(),
  interface: Joi.string().required(),
  description: Joi.string().min(3).max(255).required(),
  
  // Campi opzionali
  protocol: Joi.string().valid('tcp', 'udp', 'icmp', 'any').default('any'),
  enabled: Joi.boolean().default(true),
  sequence: Joi.number().integer().min(1),
  direction: Joi.string().valid('in', 'out').default('in'),
  log_enabled: Joi.boolean().default(false),
  
  // Configurazioni indirizzi semplificati
  source_config: Joi.object({
    type: Joi.string().valid('any', 'single', 'network').required(),
    address: Joi.when('type', { is: 'single', then: Joi.string().required() }),
    network: Joi.when('type', { is: 'network', then: Joi.string().required() }),
    port: Joi.number().integer().min(1).max(65535)
  }).default({ type: 'any' }),
  
  destination_config: Joi.object({
    type: Joi.string().valid('any', 'single', 'network').required(),
    address: Joi.when('type', { is: 'single', then: Joi.string().required() }),
    network: Joi.when('type', { is: 'network', then: Joi.string().required() }),
    port: Joi.number().integer().min(1).max(65535)
  }).default({ type: 'any' }),
  
  // Metadati opzionali
  category: Joi.string().max(50),
  tags: Joi.array().items(Joi.string()),
  risk_level: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium'),
  business_justification: Joi.string().max(1000),
  expires_at: Joi.date(),
  auto_disable_on_expiry: Joi.boolean().default(false)
});

// Schema per validazione utente
const userSchema = Joi.object({
  username: Joi.string().min(3).max(50).pattern(/^[a-zA-Z0-9_-]+$/).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`])/).required(),
  first_name: Joi.string().max(50),
  last_name: Joi.string().max(50),
  role: Joi.string().valid('admin', 'operator', 'viewer').default('viewer'),
  is_active: Joi.boolean().default(true),
  preferences: Joi.object({
    theme: Joi.string().valid('light', 'dark').default('light'),
    language: Joi.string().valid('it', 'en').default('it'),
    timezone: Joi.string().default('Europe/Rome'),
    notifications: Joi.object({
      email: Joi.boolean().default(true),
      browser: Joi.boolean().default(true),
      critical_only: Joi.boolean().default(false)
    })
  })
});

// Schema per aggiornamento utente
const userUpdateSchema = Joi.object({
  username: Joi.string().min(3).max(50).pattern(/^[a-zA-Z0-9_-]+$/),
  email: Joi.string().email(),
  password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`])/),
  first_name: Joi.string().max(50).allow(''),
  last_name: Joi.string().max(50).allow(''),
  role: Joi.string().valid('admin', 'operator', 'viewer'),
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
const uuidSchema = Joi.string().guid({ version: 'uuidv4' });

// Middleware per validazione login
const validateLogin = (req, res, next) => {
  const { error } = loginSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Dati di login non validi',
      errors: error.details.map(detail => detail.message)
    });
  }
  
  next();
};

// Middleware per validazione regola
const validateRule = (req, res, next) => {
  const { error, value } = ruleSchema.validate(req.body, { 
    allowUnknown: true,
    stripUnknown: false 
  });
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Dati regola non validi',
      errors: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }))
    });
  }
  
  req.body = value;
  next();
};

// Middleware per validazione utente
const validateUser = (req, res, next) => {
  const { error, value } = userSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Dati utente non validi',
      errors: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }))
    });
  }
  
  req.body = value;
  next();
};

// Middleware per validazione aggiornamento utente
const validateUserUpdate = (req, res, next) => {
  const { error, value } = userUpdateSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Dati aggiornamento utente non validi',
      errors: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }))
    });
  }
  
  req.body = value;
  next();
};

// Middleware per validazione UUID nei parametri
const validateUUID = (req, res, next) => {
  const { uuid } = req.params;
  const { error } = uuidSchema.validate(uuid);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'UUID non valido'
    });
  }
  
  next();
};

// Validazione query parameters per ricerca
const searchQuerySchema = Joi.object({
  search: Joi.string().max(100).allow(''),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(25),
  sortBy: Joi.string().valid('sequence', 'description', 'action', 'interface', 'created_at').default('sequence'),
  sortOrder: Joi.string().valid('asc', 'desc').default('asc'),
  enabled: Joi.boolean(),
  action: Joi.string().valid('pass', 'block', 'reject'),
  interface: Joi.string(),
  role: Joi.string().valid('admin', 'operator', 'viewer'),
  active: Joi.boolean()
});

const validateSearchQuery = (req, res, next) => {
  const { error, value } = searchQuerySchema.validate(req.query);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Parametri di ricerca non validi',
      errors: error.details.map(detail => detail.message)
    });
  }
  
  req.query = value;
  next();
};

// Validazione per operazioni batch
const batchOperationSchema = Joi.object({
  ids: Joi.array().items(Joi.alternatives().try(
    Joi.number().integer(),
    uuidSchema
  )).min(1).max(50).required(),
  operation: Joi.string().valid('enable', 'disable', 'delete').required()
});

const validateBatchOperation = (req, res, next) => {
  const { error } = batchOperationSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Operazione batch non valida',
      errors: error.details.map(detail => detail.message)
    });
  }
  
  next();
};

module.exports = {
  validateLogin,
  validateRule,
  validateUser,
  validateUserUpdate,
  validateUUID,
  validateSearchQuery,
  validateBatchOperation
};