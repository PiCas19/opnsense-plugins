// src/utils/logger.js
const winston = require('winston');
const fs = require('fs');
const path = require('path');

// Assicura che la cartella logs esista (i File transport non la creano da soli)
const logsDir = path.join(__dirname, '..', '..', 'logs');
try { fs.mkdirSync(logsDir, { recursive: true }); } catch (_) { /* ignore */ }

// === Hook per metriche (settati da monitoring.js) ===
let logEventRecorder = null;     // (level, message, meta) => void
let httpRequestRecorder = null;  // (method, route, status, durationMs) => void

function setLogEventRecorder(fn) {
  logEventRecorder = (typeof fn === 'function') ? fn : null;
}

function setHttpRequestRecorder(fn) {
  httpRequestRecorder = (typeof fn === 'function') ? fn : null;
}

// Tap di metriche nel pipeline dei format (side-effect sicuro)
// Qui evitiamo di far fallire il logging qualunque cosa accada nel recorder
const metricsTap = winston.format((info) => {
  if (logEventRecorder /* opzionale */) {
    try {
      // Puoi limitare agli errori, o registrare tutti i livelli: scegli tu.
      // Qui rimaniamo conservativi e registriamo solo gli 'error'.
      if (info.level === 'error') {
        const { message, ...rest } = info;
        logEventRecorder('error', message, rest);
      }
    } catch (_) { /* mai propagare */ }
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

// === API di integrazione metriche esposta al resto dell'app ===
logger.setLogEventRecorder = setLogEventRecorder;
logger.setHttpRequestRecorder = setHttpRequestRecorder;

// Alias retro-compatibili
logger.setMetricsRecorder = setLogEventRecorder;
// Getter comodo usato dal tuo errorHandler (non crea dipendenza)
Object.defineProperty(logger, 'metricsRecorder', {
  get() { return httpRequestRecorder; }
});

module.exports = logger;