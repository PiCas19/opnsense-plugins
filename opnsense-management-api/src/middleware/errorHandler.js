const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

// Error types and codes
const ERROR_TYPES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR: 'NOT_FOUND_ERROR',
  CONFLICT_ERROR: 'CONFLICT_ERROR',
  RATE_LIMIT_ERROR: 'RATE_LIMIT_ERROR',
  EXTERNAL_API_ERROR: 'EXTERNAL_API_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
};

const STATUS_CODES = {
  [ERROR_TYPES.VALIDATION_ERROR]: 400,
  [ERROR_TYPES.AUTHENTICATION_ERROR]: 401,
  [ERROR_TYPES.AUTHORIZATION_ERROR]: 403,
  [ERROR_TYPES.NOT_FOUND_ERROR]: 404,
  [ERROR_TYPES.CONFLICT_ERROR]: 409,
  [ERROR_TYPES.RATE_LIMIT_ERROR]: 429,
  [ERROR_TYPES.EXTERNAL_API_ERROR]: 502,
  [ERROR_TYPES.DATABASE_ERROR]: 503,
  [ERROR_TYPES.INTERNAL_SERVER_ERROR]: 500,
};

// === Error classes ===
class AppError extends Error {
  constructor(message, type = ERROR_TYPES.INTERNAL_SERVER_ERROR, statusCode = null, details = null) {
    super(message);
    this.name = this.constructor.name;
    this.type = type;
    this.statusCode = statusCode || STATUS_CODES[type] || 500;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.VALIDATION_ERROR, 400, details);
  }
}

class AuthenticationError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.AUTHENTICATION_ERROR, 401, details);
  }
}

class AuthorizationError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.AUTHORIZATION_ERROR, 403, details);
  }
}

class NotFoundError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.NOT_FOUND_ERROR, 404, details);
  }
}

class ConflictError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.CONFLICT_ERROR, 409, details);
  }
}

class RateLimitError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.RATE_LIMIT_ERROR, 429, details);
  }
}

class ExternalApiError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.EXTERNAL_API_ERROR, 502, details);
  }
}

class DatabaseError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.DATABASE_ERROR, 503, details);
  }
}

// === Utility functions ===
const determineErrorType = (error) => {
  if (error.name === 'SequelizeValidationError') return ERROR_TYPES.VALIDATION_ERROR;
  if (error.name === 'SequelizeUniqueConstraintError') return ERROR_TYPES.CONFLICT_ERROR;
  if (error.name === 'SequelizeForeignKeyConstraintError') return ERROR_TYPES.VALIDATION_ERROR;
  if (error.name === 'SequelizeConnectionError') return ERROR_TYPES.DATABASE_ERROR;

  if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
    return ERROR_TYPES.AUTHENTICATION_ERROR;
  }
  if (error.name === 'ValidationError' && error.isJoi) return ERROR_TYPES.VALIDATION_ERROR;
  if (error.type === 'entity.parse.failed') return ERROR_TYPES.VALIDATION_ERROR;
  if (error.isAxiosError) return ERROR_TYPES.EXTERNAL_API_ERROR;
  if (error instanceof AppError) return error.type;

  return ERROR_TYPES.INTERNAL_SERVER_ERROR;
};

const extractErrorDetails = (error) => {
  const details = {};
  if (error.name === 'SequelizeValidationError') {
    details.validation_errors = error.errors.map(err => ({
      field: err.path, message: err.message, value: err.value
    }));
  }
  if (error.isJoi) {
    details.validation_errors = error.details.map(detail => ({
      field: detail.path.join('.'), message: detail.message, value: detail.context?.value
    }));
  }
  if (error.array && typeof error.array === 'function') {
    details.validation_errors = error.array().map(err => ({
      field: err.path || err.param, message: err.msg, value: err.value
    }));
  }
  if (error.isAxiosError) {
    details.external_service = 'OPNsense API';
    details.status_code = error.response?.status;
    details.status_text = error.response?.statusText;
    details.url = error.config?.url;
    details.method = error.config?.method?.toUpperCase();
  }
  if (error.details) Object.assign(details, error.details);

  return Object.keys(details).length > 0 ? details : null;
};

const shouldExposeError = (error, env = process.env.NODE_ENV) => {
  if (error.isOperational) return true;
  if (env === 'development') return true;
  const safeErrors = [
    ERROR_TYPES.VALIDATION_ERROR,
    ERROR_TYPES.AUTHENTICATION_ERROR,
    ERROR_TYPES.AUTHORIZATION_ERROR,
    ERROR_TYPES.NOT_FOUND_ERROR,
    ERROR_TYPES.CONFLICT_ERROR,
    ERROR_TYPES.RATE_LIMIT_ERROR,
  ];
  return safeErrors.includes(determineErrorType(error));
};

const sanitizeErrorMessage = (error, shouldExpose) => {
  if (!shouldExpose) return 'An internal server error occurred';
  if (error.isOperational) return error.message;
  const type = determineErrorType(error);
  switch (type) {
    case ERROR_TYPES.DATABASE_ERROR:
      return 'Database service temporarily unavailable';
    case ERROR_TYPES.EXTERNAL_API_ERROR:
      return 'External service temporarily unavailable';
    default:
      return error.message || 'An error occurred';
  }
};

// === Middleware ===
const errorHandler = (error, req, res, next) => {
  const errorId = uuidv4();
  const timestamp = new Date().toISOString();

  const errorType = determineErrorType(error);
  const statusCode = error.statusCode || STATUS_CODES[errorType] || 500;
  const errorDetails = extractErrorDetails(error);
  const expose = shouldExposeError(error);

  const errorContext = {
    error_id: errorId,
    timestamp,
    type: errorType,
    message: error.message,
    stack: error.stack,
    status_code: statusCode,
    url: req.originalUrl || req.url,
    method: req.method,
    user_id: req.user?.id || null,
    user_agent: req.get('User-Agent'),
    ip_address: req.ip,
    correlation_id: req.correlationId,
    details: errorDetails,
  };

  if (statusCode >= 500) {
    logger.error('Internal server error', errorContext);
  } else if (statusCode >= 400) {
    logger.warn('Client error', errorContext);
  } else {
    logger.info('Error handled', errorContext);
  }

  // Non richiede più direttamente monitoring, così evitiamo il ciclo
  if (logger.metricsRecorder) {
    try {
      logger.metricsRecorder(
        req.method,
        req.route?.path || req.path,
        statusCode,
        Date.now() - (req.startTime || Date.now())
      );
    } catch (_) {}
  }

  const responseBody = {
    success: false,
    error: sanitizeErrorMessage(error, expose),
    code: errorType,
    error_id: errorId,
    timestamp,
  };

  if (expose && errorDetails) responseBody.details = errorDetails;
  if (process.env.NODE_ENV === 'development' && error.stack) {
    responseBody.stack = error.stack;
  }

  res.status(statusCode).json(responseBody);
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

const notFoundHandler = (req, res, next) => {
  next(new NotFoundError(`Route ${req.method} ${req.originalUrl} not found`, {
    method: req.method,
    url: req.originalUrl,
    available_routes: req.app._router?.stack
      ?.filter(layer => layer.route)
      ?.map(layer => ({
        method: Object.keys(layer.route.methods)[0]?.toUpperCase(),
        path: layer.route.path,
      })) || [],
  }));
};

const handleUnhandledRejection = () => {
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise: promise.toString(),
    });
    if (process.env.NODE_ENV === 'production') {
      setTimeout(() => process.exit(1), 1000);
    }
  });
};

const handleUncaughtException = () => {
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', { message: error.message, stack: error.stack });
    process.exit(1);
  });
};

const initializeErrorHandling = () => {
  handleUnhandledRejection();
  handleUncaughtException();
  logger.info('Error handling initialized');
};

module.exports = {
  errorHandler,
  asyncHandler,
  notFoundHandler,
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ExternalApiError,
  DatabaseError,
  determineErrorType,
  extractErrorDetails,
  shouldExposeError,
  sanitizeErrorMessage,
  initializeErrorHandling,
  ERROR_TYPES,
  STATUS_CODES,
};