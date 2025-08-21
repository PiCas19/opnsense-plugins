const logger = require('../utils/logger');

// 404 handler
const notFound = (req, res, next) => {
  const error = new Error(`Endpoint non trovato: ${req.originalUrl}`);
  error.status = 404;
  next(error);
};

// Error handler principale
const errorHandler = (err, req, res, next) => {
  let statusCode = err.status || err.statusCode || 500;
  let message = err.message || 'Errore interno del server';

  // Log dell'errore
  logger.error('Errore nell\'applicazione', {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user?.username
  });

  // Gestione errori specifici
  
  // Errori di validazione Joi
  if (err.isJoi) {
    statusCode = 400;
    message = 'Dati non validi';
  }

  // Errori JWT
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Token non valido';
  }

  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token scaduto';
  }

  // Errori di connessione
  if (err.code === 'ECONNREFUSED') {
    statusCode = 503;
    message = 'Servizio non disponibile';
  }

  if (err.code === 'ETIMEDOUT') {
    statusCode = 504;
    message = 'Timeout della richiesta';
  }

  // Errori Axios
  if (err.response) {
    statusCode = err.response.status;
    message = err.response.data?.message || message;
  }

  // Errori Sequelize
  if (err.name === 'SequelizeValidationError') {
    statusCode = 400;
    message = 'Errore di validazione database';
  }

  if (err.name === 'SequelizeUniqueConstraintError') {
    statusCode = 409;
    message = 'Risorsa già esistente';
  }

  if (err.name === 'SequelizeForeignKeyConstraintError') {
    statusCode = 400;
    message = 'Violazione integrità referenziale';
  }

  if (err.name === 'SequelizeConnectionError') {
    statusCode = 503;
    message = 'Errore di connessione al database';
  }

  // Errori di cast/validazione
  if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Risorsa non trovata';
  }

  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = Object.values(err.errors).map(val => val.message).join(', ');
  }

  // Errori di duplicazione
  if (err.code === 11000) {
    statusCode = 400;
    message = 'Risorsa già esistente';
  }

  // Errori OPNsense API specifici
  if (err.endpoint && err.method) {
    logger.error('OPNsense API Error', {
      endpoint: err.endpoint,
      method: err.method,
      operation: err.operation,
      originalError: err.originalError?.message
    });
    
    if (statusCode === 500) {
      statusCode = 502;
      message = 'Errore comunicazione con OPNsense';
    }
  }

  // Risposta di errore
  const errorResponse = {
    success: false,
    message,
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    method: req.method
  };

  // Aggiungi dettagli in development
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
    errorResponse.details = {
      name: err.name,
      code: err.code,
      originalError: err.originalError
    };
  }

  res.status(statusCode).json(errorResponse);
};

// Async error handler wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  notFound,
  errorHandler,
  asyncHandler
};