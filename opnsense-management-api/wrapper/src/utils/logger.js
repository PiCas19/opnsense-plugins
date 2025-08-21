const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Assicurati che la cartella logs esista
const logsDir = path.join(process.cwd(), 'logs');
try {
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }
} catch (error) {
  console.error('Warning: Could not create logs directory:', error.message);
}

// Definisci i livelli di log
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3
};

// Colori per i livelli (solo per console)
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  debug: 'blue'
};

winston.addColors(colors);

// Formato per i log
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Formato per console (development)
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let log = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length) {
      log += `\n${JSON.stringify(meta, null, 2)}`;
    }
    return log;
  })
);

// Configurazione transports
const transports = [];

// Console transport (sempre attivo in development)
if (process.env.NODE_ENV !== 'production') {
  transports.push(
    new winston.transports.Console({
      level: 'debug',
      format: consoleFormat,
      handleExceptions: true,
      handleRejections: true
    })
  );
}

// File transports (con fallback sicuro)
try {
  // Log errori
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      format: logFormat,
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      handleExceptions: true
    })
  );
  
  // Log combinati
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      format: logFormat,
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  );
} catch (error) {
  console.warn('Warning: Could not setup file logging:', error.message);
  console.warn('Continuing with console-only logging...');
}

// Crea logger con fallback robusto
let logger;

try {
  logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    levels,
    format: logFormat,
    transports,
    exitOnError: false,
    silent: false
  });

  // Gestione eccezioni non catturate
  logger.exceptions.handle(
    new winston.transports.Console({
      format: consoleFormat
    })
  );

  // Test del logger
  logger.info('Logger initialized successfully');

} catch (error) {
  console.error('Failed to initialize Winston logger:', error.message);
  console.log('Falling back to console logger...');
  
  // Fallback console logger
  logger = {
    error: (...args) => console.error('ERROR:', ...args),
    warn: (...args) => console.warn('WARN:', ...args),
    info: (...args) => console.log('INFO:', ...args),
    debug: (...args) => {
      if (process.env.NODE_ENV !== 'production') {
        console.log('DEBUG:', ...args);
      }
    },
    
    // Helper methods per compatibilità
    logRequest: (req, res, responseTime) => {
      console.log('HTTP Request:', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        statusCode: res.statusCode,
        responseTime: `${responseTime}ms`
      });
    },
    
    logApiCall: (service, method, url, duration, success = true) => {
      const level = success ? 'INFO' : 'ERROR';
      console.log(`${level} API Call:`, {
        service,
        method,
        url,
        duration: `${duration}ms`,
        success
      });
    },
    
    logSecurityEvent: (event, details) => {
      console.warn('SECURITY EVENT:', {
        event,
        ...details,
        timestamp: new Date().toISOString()
      });
    }
  };
}

// Gestione promise rejection non gestite
process.on('unhandledRejection', (reason, promise) => {
  if (logger && logger.error) {
    logger.error('Unhandled Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise
    });
  } else {
    console.error('Unhandled Rejection:', reason);
  }
});

// Helper methods per logging strutturato (se non già definiti)
if (logger && !logger.logRequest) {
  logger.logRequest = (req, res, responseTime) => {
    logger.info('HTTP Request', {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      user: req.user?.username
    });
  };

  logger.logApiCall = (service, method, url, duration, success = true) => {
    const level = success ? 'info' : 'error';
    logger[level]('API Call', {
      service,
      method,
      url,
      duration: `${duration}ms`,
      success
    });
  };

  logger.logSecurityEvent = (event, details) => {
    logger.warn('Security Event', {
      event,
      ...details,
      timestamp: new Date().toISOString()
    });
  };
}

// In produzione, log anche su console se specificato
if (process.env.NODE_ENV === 'production' && process.env.LOG_TO_CONSOLE === 'true' && logger.add) {
  try {
    logger.add(
      new winston.transports.Console({
        level: 'info',
        format: winston.format.simple()
      })
    );
  } catch (error) {
    console.warn('Could not add console transport to production logger');
  }
}

module.exports = logger;