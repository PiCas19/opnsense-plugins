const logger = require('../utils/logger');

// ===============================
// HANDLER ERRORI SPECIFICI
// ===============================

/**
 * Gestisce errori di validazione Joi
 */
const handleJoiError = (err) => {
  return {
    statusCode: 400,
    message: 'Dati di input non validi',
    errors: err.details?.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message,
      value: detail.context?.value
    })) || []
  };
};

/**
 * Gestisce errori JWT
 */
const handleJWTError = (err) => {
  const jwtErrors = {
    'JsonWebTokenError': {
      statusCode: 401,
      message: 'Token di accesso non valido',
      code: 'INVALID_TOKEN'
    },
    'TokenExpiredError': {
      statusCode: 401,
      message: 'Token di accesso scaduto',
      code: 'TOKEN_EXPIRED'
    },
    'NotBeforeError': {
      statusCode: 401,
      message: 'Token non ancora valido',
      code: 'TOKEN_NOT_ACTIVE'
    }
  };

  return jwtErrors[err.name] || {
    statusCode: 401,
    message: 'Errore di autenticazione',
    code: 'AUTH_ERROR'
  };
};

/**
 * Gestisce errori di connessione di rete
 */
const handleNetworkError = (err) => {
  const networkErrors = {
    'ECONNREFUSED': {
      statusCode: 503,
      message: 'Servizio non disponibile - connessione rifiutata',
      code: 'SERVICE_UNAVAILABLE'
    },
    'ETIMEDOUT': {
      statusCode: 504,
      message: 'Timeout della richiesta',
      code: 'REQUEST_TIMEOUT'
    },
    'ENOTFOUND': {
      statusCode: 503,
      message: 'Servizio non raggiungibile',
      code: 'SERVICE_UNREACHABLE'
    },
    'ECONNRESET': {
      statusCode: 502,
      message: 'Connessione interrotta dal server',
      code: 'CONNECTION_RESET'
    }
  };

  return networkErrors[err.code] || {
    statusCode: 502,
    message: 'Errore di comunicazione di rete',
    code: 'NETWORK_ERROR'
  };
};

/**
 * Gestisce errori Axios/HTTP
 */
const handleAxiosError = (err) => {
  if (err.response) {
    // Errore con risposta dal server
    const status = err.response.status;
    const data = err.response.data;
    
    return {
      statusCode: status,
      message: data?.message || `Errore HTTP ${status}`,
      code: data?.code || 'HTTP_ERROR',
      details: data?.errors || data?.details
    };
  }
  
  if (err.request) {
    // Richiesta fatta ma nessuna risposta
    return {
      statusCode: 503,
      message: 'Servizio non disponibile - nessuna risposta',
      code: 'NO_RESPONSE'
    };
  }
  
  // Errore nella configurazione della richiesta
  return {
    statusCode: 500,
    message: 'Errore nella configurazione della richiesta',
    code: 'REQUEST_CONFIG_ERROR'
  };
};

/**
 * Gestisce errori Sequelize (database)
 */
const handleSequelizeError = (err) => {
  const sequelizeErrors = {
    'SequelizeValidationError': {
      statusCode: 400,
      message: 'Errore di validazione database',
      code: 'VALIDATION_ERROR',
      errors: err.errors?.map(e => ({
        field: e.path,
        message: e.message,
        value: e.value
      }))
    },
    'SequelizeUniqueConstraintError': {
      statusCode: 409,
      message: 'Violazione constraint di unicità',
      code: 'DUPLICATE_ENTRY',
      field: err.errors?.[0]?.path
    },
    'SequelizeForeignKeyConstraintError': {
      statusCode: 400,
      message: 'Violazione integrità referenziale',
      code: 'FOREIGN_KEY_VIOLATION',
      details: err.parent?.detail
    },
    'SequelizeConnectionError': {
      statusCode: 503,
      message: 'Errore di connessione al database',
      code: 'DATABASE_CONNECTION_ERROR'
    },
    'SequelizeConnectionTimedOutError': {
      statusCode: 504,
      message: 'Timeout connessione database',
      code: 'DATABASE_TIMEOUT'
    },
    'SequelizeAccessDeniedError': {
      statusCode: 503,
      message: 'Accesso negato al database',
      code: 'DATABASE_ACCESS_DENIED'
    }
  };

  return sequelizeErrors[err.name] || {
    statusCode: 500,
    message: 'Errore database generico',
    code: 'DATABASE_ERROR'
  };
};

/**
 * Gestisce errori di validazione generici
 */
const handleValidationError = (err) => {
  return {
    statusCode: 400,
    message: 'Errore di validazione',
    code: 'VALIDATION_ERROR',
    errors: err.errors ? Object.values(err.errors).map(e => e.message) : [err.message]
  };
};

/**
 * Gestisce errori di cast (MongoDB style)
 */
const handleCastError = (err) => {
  return {
    statusCode: 400,
    message: 'Formato dati non valido',
    code: 'INVALID_DATA_FORMAT',
    field: err.path,
    value: err.value
  };
};

/**
 * Gestisce errori di duplicazione (MongoDB style)
 */
const handleDuplicateError = (err) => {
  const field = Object.keys(err.keyValue)[0];
  return {
    statusCode: 409,
    message: `Valore duplicato per il campo: ${field}`,
    code: 'DUPLICATE_VALUE',
    field,
    value: err.keyValue[field]
  };
};

/**
 * Gestisce errori OPNsense API specifici
 */
const handleOPNsenseError = (err) => {
  logger.error('Errore API OPNsense', {
    endpoint: err.endpoint,
    method: err.method,
    operation: err.operation,
    originalError: err.originalError?.message,
    statusCode: err.statusCode
  });

  // Determina il codice di stato appropriato
  let statusCode = 502; // Bad Gateway di default
  let message = 'Errore di comunicazione con OPNsense';
  let code = 'OPNSENSE_ERROR';

  if (err.statusCode) {
    if (err.statusCode >= 400 && err.statusCode < 500) {
      statusCode = err.statusCode;
      message = 'Errore nella richiesta a OPNsense';
      code = 'OPNSENSE_CLIENT_ERROR';
    } else if (err.statusCode >= 500) {
      statusCode = 502;
      message = 'Errore interno di OPNsense';
      code = 'OPNSENSE_SERVER_ERROR';
    }
  }

  return {
    statusCode,
    message,
    code,
    operation: err.operation,
    endpoint: err.endpoint
  };
};

// ===============================
// MIDDLEWARE PRINCIPALI
// ===============================

/**
 * Handler per endpoint non trovati (404)
 */
const notFound = (req, res, next) => {
  const error = new Error(`Endpoint non trovato: ${req.method} ${req.originalUrl}`);
  error.status = 404;
  error.code = 'ENDPOINT_NOT_FOUND';
  
  logger.warn('Endpoint non trovato', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user?.username
  });
  
  next(error);
};

/**
 * Error handler principale
 */
const errorHandler = (err, req, res, next) => {
  let statusCode = err.status || err.statusCode || 500;
  let message = err.message || 'Errore interno del server';
  let code = err.code || 'INTERNAL_ERROR';
  let errors = null;
  let details = null;

  // Log dell'errore con dettagli contestuali
  const errorContext = {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user?.username,
    body: req.method !== 'GET' ? req.body : undefined,
    query: Object.keys(req.query).length > 0 ? req.query : undefined
  };

  // Log con livello appropriato
  if (statusCode >= 500) {
    logger.error('Errore server interno', errorContext);
  } else if (statusCode >= 400) {
    logger.warn('Errore client', errorContext);
  }

  // Gestione errori specifici
  let errorResult = null;

  if (err.isJoi) {
    errorResult = handleJoiError(err);
  } else if (['JsonWebTokenError', 'TokenExpiredError', 'NotBeforeError'].includes(err.name)) {
    errorResult = handleJWTError(err);
  } else if (err.code && ['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET'].includes(err.code)) {
    errorResult = handleNetworkError(err);
  } else if (err.isAxiosError || err.response) {
    errorResult = handleAxiosError(err);
  } else if (err.name && err.name.startsWith('Sequelize')) {
    errorResult = handleSequelizeError(err);
  } else if (err.name === 'ValidationError') {
    errorResult = handleValidationError(err);
  } else if (err.name === 'CastError') {
    errorResult = handleCastError(err);
  } else if (err.code === 11000) {
    errorResult = handleDuplicateError(err);
  } else if (err.endpoint && err.method) {
    errorResult = handleOPNsenseError(err);
  }

  // Applica risultato gestione errore specifica
  if (errorResult) {
    statusCode = errorResult.statusCode;
    message = errorResult.message;
    code = errorResult.code;
    errors = errorResult.errors;
    details = errorResult.details;
  }

  // Costruisci risposta di errore
  const errorResponse = {
    success: false,
    message,
    code,
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    method: req.method
  };

  // Aggiungi errori dettagliati se presenti
  if (errors) {
    errorResponse.errors = errors;
  }

  // Aggiungi dettagli se presenti
  if (details) {
    errorResponse.details = details;
  }

  // Aggiungi informazioni aggiuntive in development
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
    errorResponse.debug = {
      name: err.name,
      code: err.code,
      originalError: err.originalError ? {
        message: err.originalError.message,
        stack: err.originalError.stack
      } : undefined
    };
  }

  // Aggiungi header appropriati
  res.set({
    'Content-Type': 'application/json',
    'X-Error-Code': code
  });

  // Aggiungi Retry-After per errori temporanei
  if ([429, 503, 504].includes(statusCode)) {
    res.set('Retry-After', '60'); // 60 secondi
    errorResponse.retry_after = 60;
  }

  res.status(statusCode).json(errorResponse);
};

/**
 * Async error handler wrapper
 * Cattura errori da funzioni async e li passa al middleware di gestione errori
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Wrapper per operazioni con timeout
 */
const withTimeout = (fn, timeoutMs = 30000) => {
  return async (req, res, next) => {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error('Operazione scaduta per timeout'));
      }, timeoutMs);
    });

    try {
      await Promise.race([
        fn(req, res, next),
        timeoutPromise
      ]);
    } catch (error) {
      if (error.message.includes('timeout')) {
        error.status = 504;
        error.code = 'OPERATION_TIMEOUT';
      }
      next(error);
    }
  };
};

/**
 * Handler per errori non catturati
 */
const handleUncaughtErrors = () => {
  // Gestisce eccezioni non catturate
  process.on('uncaughtException', (error) => {
    logger.error('Eccezione non catturata', {
      error: error.message,
      stack: error.stack
    });
    
    // Graceful shutdown
    process.exit(1);
  });

  // Gestisce promise rejection non gestite
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Promise rejection non gestita', {
      reason: reason instanceof Error ? reason.message : reason,
      stack: reason instanceof Error ? reason.stack : undefined,
      promise: promise.toString()
    });
    
    // Non terminare il processo per unhandled rejections in produzione
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  });
};

/**
 * Middleware per logging delle performance
 */
const performanceLogger = (req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log solo se la richiesta è lenta (>1000ms) o ha errori
    if (duration > 1000 || res.statusCode >= 400) {
      logger.warn('Richiesta lenta o con errori', {
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        duration: `${duration}ms`,
        user: req.user?.username,
        ip: req.ip
      });
    }
  });
  
  next();
};

// ===============================
// UTILITY
// ===============================

/**
 * Crea errore HTTP con codice specifico
 */
const createHttpError = (statusCode, message, code = null) => {
  const error = new Error(message);
  error.status = statusCode;
  error.code = code || `HTTP_${statusCode}`;
  return error;
};

/**
 * Crea errore di validazione
 */
const createValidationError = (message, errors = []) => {
  const error = new Error(message);
  error.status = 400;
  error.code = 'VALIDATION_ERROR';
  error.errors = errors;
  return error;
};

/**
 * Crea errore OPNsense
 */
const createOPNsenseError = (message, endpoint, method, operation) => {
  const error = new Error(message);
  error.status = 502;
  error.code = 'OPNSENSE_ERROR';
  error.endpoint = endpoint;
  error.method = method;
  error.operation = operation;
  return error;
};

module.exports = {
  // Middleware principali
  notFound,
  errorHandler,
  asyncHandler,
  withTimeout,
  performanceLogger,
  
  // Gestori errori specifici
  handleJoiError,
  handleJWTError,
  handleNetworkError,
  handleAxiosError,
  handleSequelizeError,
  handleOPNsenseError,
  
  // Utility
  createHttpError,
  createValidationError,
  createOPNsenseError,
  handleUncaughtErrors
};