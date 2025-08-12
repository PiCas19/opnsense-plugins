const winston = require('winston');
const { metricsHelpers } = require('../config/monitoring');

// Define custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.json()
);

// Create logger instance
const logger = winston.createLogger({
  level: 'info',
  format: logFormat,
  transports: [
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    // File transport for production logs
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
    }),
  ],
});

// Middleware to add metrics for error logs
logger.on('data', (log) => {
  if (log.level === 'error') {
    metricsHelpers.recordLogEvent('error', log.message, log.metadata);
  }
});

module.exports = logger;