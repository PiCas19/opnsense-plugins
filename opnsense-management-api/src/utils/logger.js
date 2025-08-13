// src/utils/logger.js
const winston = require('winston');
const fs = require('fs');
const path = require('path');

// Assicura che la cartella logs esista (i File transport non la creano da soli)
const logsDir = path.join(__dirname, '..', '..', 'logs');
try { fs.mkdirSync(logsDir, { recursive: true }); } catch (_) { /* ignore */ }

// Carica i helpers di monitoring in modo "safe"
let monitoring = {};
try {
  monitoring = require('../config/monitoring');
} catch (_) {
  monitoring = {};
}

// Sorgente potenziale delle funzioni di metrica
const metricsSource = monitoring.metricsHelpers || monitoring;

// Scegli in modo resiliente la funzione di registrazione eventi (o no-op)
const recordFn =
  metricsSource && typeof metricsSource.recordLogEvent === 'function'
    ? metricsSource.recordLogEvent
    : metricsSource && typeof metricsSource.recordEvent === 'function'
      ? metricsSource.recordEvent
      : null;

function tryRecord(level, message, metadata) {
  if (!recordFn) return;         // se non disponibile, non fare nulla
  try {
    recordFn(level, message, metadata || {});
  } catch (_) {
    // Mai far fallire il logger per colpa delle metriche
  }
}

// Tap di metriche nel pipeline dei format (side-effect sicuro)
const metricsTap = winston.format((info) => {
  if (info.level === 'error') {
    const { message, ...rest } = info;
    tryRecord('error', message, rest);
  }
  return info;
});

// Formati
const jsonFormat = winston.format.combine(
  metricsTap(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.json()
);

const consoleFormat = winston.format.combine(
  metricsTap(),
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...rest }) => {
    const meta = Object.keys(rest).length ? ` ${JSON.stringify(rest)}` : '';
    return `${timestamp} ${level}: ${message}${meta}`;
  })
);

// Istanza logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: jsonFormat,
  transports: [
    new winston.transports.Console({ format: consoleFormat }),
    new winston.transports.File({ filename: path.join(logsDir, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(logsDir, 'combined.log') })
  ]
});

// Non far mai propagare errori dal logger
logger.on('error', () => { /* swallow logger errors */ });

module.exports = logger;