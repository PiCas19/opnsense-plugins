// src/middleware/rateLimit.js
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// Helper per comporre più middleware in sequenza
const compose = (middlewares) => (req, res, next) => {
  let i = 0;
  const run = (err) => {
    if (err) return next(err);
    const mw = middlewares[i++];
    if (!mw) return next();
    try { mw(req, res, run); } catch (e) { next(e); }
  };
  run();
};

// Factory: express-rate-limit v7 (nessuna opzione deprecata)
function createRateLimiter({ windowMs = 15 * 60 * 1000, max = 100, message, skip } = {}) {
  return rateLimit({
    windowMs,
    max,
    message: message || { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip,
  });
}

// Factory: express-slow-down v2 (niente `headers`, `delayMs` come funzione)
function createSlowDown({ windowMs = 60 * 1000, delayAfter = 50, delayStepMs = 1000 } = {}) {
  return slowDown({
    windowMs,
    delayAfter,
    // Nuova API: calcolo del ritardo per chiamata oltre la soglia
    delayMs: (used, req) => {
      const limit = req.slowDown.limit; // impostato da express-slow-down
      const over = Math.max(0, used - limit);
      return over * delayStepMs;
    },
    // Disattiva il warning di migrazione per delayMs se presente
    validate: { delayMs: false },
  });
}

// Catene predefinite
const generalChain = compose([
  createSlowDown({ windowMs: 60 * 1000, delayAfter: 80, delayStepMs: 250 }),
  createRateLimiter({ windowMs: 60 * 1000, max: 500 }),
]);

const writeChain = compose([
  createSlowDown({ windowMs: 60 * 1000, delayAfter: 30, delayStepMs: 500 }),
  createRateLimiter({ windowMs: 60 * 1000, max: 200 }),
]);

// Middleware dinamico per route sensibili / scritture
function dynamicRateLimit(req, res, next) {
  const p = req.path || '';
  if (req.method !== 'GET') return writeChain(req, res, next);
  if (p.includes('/firewall') || p.includes('/admin') || p.includes('/policies')) {
    return writeChain(req, res, next);
  }
  return generalChain(req, res, next);
}

module.exports = {
  createRateLimiter,
  createSlowDown,
  dynamicRateLimit,
};