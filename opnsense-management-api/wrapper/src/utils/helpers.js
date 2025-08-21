/**
 * Funzioni helper generiche per l'applicazione
 */

const crypto = require('crypto');
const { Op } = require('sequelize');

/**
 * Genera una stringa casuale
 */
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Genera un token sicuro
 */
function generateSecureToken(length = 64) {
  return crypto.randomBytes(length).toString('base64url');
}

/**
 * Hash sicuro di una stringa
 */
function hashString(str, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(str).digest('hex');
}

/**
 * Valida formato email
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Valida formato IPv4
 */
function isValidIPv4(ip) {
  const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
  return ipv4Regex.test(ip);
}

/**
 * Valida formato CIDR
 */
function isValidCIDR(cidr) {
  const cidrRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[1-2][0-9]|[0-9])$/;
  return cidrRegex.test(cidr);
}

/**
 * Valida porta di rete
 */
function isValidPort(port) {
  const portNum = parseInt(port, 10);
  return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
}

/**
 * Valida UUID v4
 */
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Sanitizza stringa per output sicuro
 */
function sanitizeString(str, maxLength = 255) {
  if (typeof str !== 'string') return '';
  return str.trim().substring(0, maxLength);
}

/**
 * Formatta bytes in formato leggibile
 */
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Formatta durata in formato leggibile
 */
function formatDuration(milliseconds) {
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

/**
 * Calcola hash di un oggetto per caching
 */
function objectHash(obj) {
  const str = JSON.stringify(obj, Object.keys(obj).sort());
  return crypto.createHash('md5').update(str).digest('hex');
}

/**
 * Deep clone di un oggetto
 */
function deepClone(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime());
  if (obj instanceof Array) return obj.map(item => deepClone(item));
  if (typeof obj === 'object') {
    const cloned = {};
    Object.keys(obj).forEach(key => {
      cloned[key] = deepClone(obj[key]);
    });
    return cloned;
  }
}

/**
 * Merge di oggetti profondi
 */
function deepMerge(target, source) {
  const result = { ...target };
  
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(result[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  
  return result;
}

/**
 * Estrae IP da request object
 */
function getClientIP(req) {
  return req.ip || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress ||
         req.headers['x-forwarded-for']?.split(',')[0] ||
         req.headers['x-real-ip'] ||
         'unknown';
}

/**
 * Costruisce filtri Sequelize da query parameters
 */
function buildSequelizeFilters(query) {
  const filters = {};
  
  // Filtri booleani
  if (query.enabled !== undefined) {
    filters.enabled = query.enabled === 'true';
  }
  
  if (query.is_active !== undefined) {
    filters.is_active = query.is_active === 'true';
  }
  
  // Filtri enum
  if (query.action) {
    filters.action = query.action;
  }
  
  if (query.role) {
    filters.role = query.role;
  }
  
  if (query.interface) {
    filters.interface = query.interface;
  }
  
  // Filtri di ricerca testuale
  if (query.search) {
    filters[Op.or] = [
      { description: { [Op.iLike]: `%${query.search}%` } },
      { username: { [Op.iLike]: `%${query.search}%` } },
      { email: { [Op.iLike]: `%${query.search}%` } }
    ];
  }
  
  // Filtri di data
  if (query.created_after) {
    filters.created_at = { [Op.gte]: new Date(query.created_after) };
  }
  
  if (query.created_before) {
    filters.created_at = { 
      ...filters.created_at,
      [Op.lte]: new Date(query.created_before) 
    };
  }
  
  return filters;
}

/**
 * Costruisce opzioni di ordinamento Sequelize
 */
function buildSequelizeOrder(sortBy = 'created_at', sortOrder = 'desc') {
  const validSortOrders = ['asc', 'desc'];
  const order = validSortOrders.includes(sortOrder.toLowerCase()) ? 
                sortOrder.toLowerCase() : 'desc';
  
  return [[sortBy, order]];
}

/**
 * Calcola offset per paginazione
 */
function calculateOffset(page = 1, limit = 25) {
  const pageNum = Math.max(1, parseInt(page, 10));
  const limitNum = Math.max(1, Math.min(100, parseInt(limit, 10)));
  
  return {
    offset: (pageNum - 1) * limitNum,
    limit: limitNum,
    page: pageNum
  };
}

/**
 * Formatta risposta paginata
 */
function formatPaginatedResponse(data, count, page, limit) {
  const totalPages = Math.ceil(count / limit);
  
  return {
    data,
    meta: {
      total: count,
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
      pages: totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  };
}

/**
 * Delay asincrono
 */
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry con backoff esponenziale
 */
async function retryWithBackoff(fn, maxRetries = 3, baseDelay = 1000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt === maxRetries) throw error;
      
      const delayMs = baseDelay * Math.pow(2, attempt - 1);
      await delay(delayMs);
    }
  }
}

/**
 * Valida e normalizza configurazione indirizzo
 */
function normalizeAddressConfig(config) {
  if (!config || typeof config !== 'object') {
    return { type: 'any' };
  }
  
  const normalized = { type: config.type || 'any' };
  
  switch (normalized.type) {
    case 'single':
      if (config.address && isValidIPv4(config.address)) {
        normalized.address = config.address;
      } else {
        throw new Error('Invalid IP address for single type');
      }
      break;
      
    case 'network':
      if (config.network && isValidCIDR(config.network)) {
       normalized.network = config.network;
     } else {
       throw new Error('Invalid CIDR notation for network type');
     }
     break;
     
   case 'any':
   default:
     normalized.type = 'any';
     break;
 }
 
 // Aggiungi porta se specificata
 if (config.port && isValidPort(config.port)) {
   normalized.port = parseInt(config.port, 10);
 }
 
 return normalized;
}

/**
* Converte configurazione indirizzo in stringa leggibile
*/
function addressConfigToString(config) {
 if (!config || config.type === 'any') {
   return 'any';
 }
 
 switch (config.type) {
   case 'single':
     return config.port ? `${config.address}:${config.port}` : config.address;
   case 'network':
     return config.port ? `${config.network}:${config.port}` : config.network;
   default:
     return 'any';
 }
}

/**
* Genera nome file sicuro
*/
function generateSafeFilename(originalName, maxLength = 100) {
 const safeName = originalName
   .replace(/[^a-zA-Z0-9.-]/g, '_')
   .replace(/_{2,}/g, '_')
   .substring(0, maxLength);
 
 const timestamp = Date.now();
 return `${timestamp}_${safeName}`;
}

/**
* Converte stringa in slug URL-safe
*/
function slugify(text) {
 return text
   .toString()
   .toLowerCase()
   .trim()
   .replace(/\s+/g, '-')
   .replace(/[^\w\-]+/g, '')
   .replace(/\-\-+/g, '-')
   .replace(/^-+/, '')
   .replace(/-+$/, '');
}

/**
* Valida e normalizza tag array
*/
function normalizeTags(tags) {
 if (!Array.isArray(tags)) return [];
 
 return tags
   .filter(tag => typeof tag === 'string' && tag.trim().length > 0)
   .map(tag => tag.trim().toLowerCase())
   .filter((tag, index, arr) => arr.indexOf(tag) === index) // rimuovi duplicati
   .slice(0, 10); // massimo 10 tag
}

/**
* Calcola score di sicurezza password
*/
function calculatePasswordStrength(password) {
 let score = 0;
 const checks = {
   length: password.length >= 8,
   lowercase: /[a-z]/.test(password),
   uppercase: /[A-Z]/.test(password),
   numbers: /\d/.test(password),
   symbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password),
   noCommon: !['password', '123456', 'qwerty', 'admin'].includes(password.toLowerCase())
 };
 
 Object.values(checks).forEach(check => {
   if (check) score += 1;
 });
 
 const strength = score < 3 ? 'weak' : score < 5 ? 'medium' : 'strong';
 
 return {
   score,
   maxScore: Object.keys(checks).length,
   strength,
   checks
 };
}

/**
* Formatta uptime in formato leggibile
*/
function formatUptime(uptimeSeconds) {
 const days = Math.floor(uptimeSeconds / 86400);
 const hours = Math.floor((uptimeSeconds % 86400) / 3600);
 const minutes = Math.floor((uptimeSeconds % 3600) / 60);
 const seconds = Math.floor(uptimeSeconds % 60);
 
 const parts = [];
 if (days > 0) parts.push(`${days}d`);
 if (hours > 0) parts.push(`${hours}h`);
 if (minutes > 0) parts.push(`${minutes}m`);
 if (seconds > 0) parts.push(`${seconds}s`);
 
 return parts.join(' ') || '0s';
}

/**
* Limita rate per operazioni costose
*/
class RateLimiter {
 constructor(windowMs = 60000, maxRequests = 10) {
   this.windowMs = windowMs;
   this.maxRequests = maxRequests;
   this.requests = new Map();
 }
 
 isAllowed(key) {
   const now = Date.now();
   const windowStart = now - this.windowMs;
   
   if (!this.requests.has(key)) {
     this.requests.set(key, []);
   }
   
   const userRequests = this.requests.get(key);
   
   // Rimuovi richieste vecchie
   const validRequests = userRequests.filter(time => time > windowStart);
   
   if (validRequests.length >= this.maxRequests) {
     return false;
   }
   
   validRequests.push(now);
   this.requests.set(key, validRequests);
   
   return true;
 }
 
 getRemainingRequests(key) {
   const now = Date.now();
   const windowStart = now - this.windowMs;
   
   if (!this.requests.has(key)) {
     return this.maxRequests;
   }
   
   const userRequests = this.requests.get(key);
   const validRequests = userRequests.filter(time => time > windowStart);
   
   return Math.max(0, this.maxRequests - validRequests.length);
 }
 
 getResetTime(key) {
   const now = Date.now();
   
   if (!this.requests.has(key)) {
     return now;
   }
   
   const userRequests = this.requests.get(key);
   if (userRequests.length === 0) {
     return now;
   }
   
   return userRequests[0] + this.windowMs;
 }
}

/**
* Cache semplice in memoria con TTL
*/
class SimpleCache {
 constructor(defaultTTL = 300000) { // 5 minuti default
   this.cache = new Map();
   this.timers = new Map();
   this.defaultTTL = defaultTTL;
 }
 
 set(key, value, ttl = this.defaultTTL) {
   // Pulisci timer esistente
   if (this.timers.has(key)) {
     clearTimeout(this.timers.get(key));
   }
   
   // Imposta valore
   this.cache.set(key, value);
   
   // Imposta timer per scadenza
   const timer = setTimeout(() => {
     this.delete(key);
   }, ttl);
   
   this.timers.set(key, timer);
 }
 
 get(key) {
   return this.cache.get(key);
 }
 
 has(key) {
   return this.cache.has(key);
 }
 
 delete(key) {
   if (this.timers.has(key)) {
     clearTimeout(this.timers.get(key));
     this.timers.delete(key);
   }
   return this.cache.delete(key);
 }
 
 clear() {
   for (const timer of this.timers.values()) {
     clearTimeout(timer);
   }
   this.timers.clear();
   this.cache.clear();
 }
 
 size() {
   return this.cache.size;
 }
 
 keys() {
   return Array.from(this.cache.keys());
 }
}

/**
* Escape HTML per prevenire XSS
*/
function escapeHtml(text) {
 const map = {
   '&': '&amp;',
   '<': '&lt;',
   '>': '&gt;',
   '"': '&quot;',
   "'": '&#039;'
 };
 
 return text.replace(/[&<>"']/g, m => map[m]);
}

/**
* Converte timestamp in formato relativo
*/
function timeAgo(date) {
 const now = new Date();
 const diffMs = now - new Date(date);
 const diffSecs = Math.floor(diffMs / 1000);
 const diffMins = Math.floor(diffSecs / 60);
 const diffHours = Math.floor(diffMins / 60);
 const diffDays = Math.floor(diffHours / 24);
 
 if (diffSecs < 60) return 'appena ora';
 if (diffMins < 60) return `${diffMins} minuto${diffMins !== 1 ? 'i' : ''} fa`;
 if (diffHours < 24) return `${diffHours} ora${diffHours !== 1 ? 'e' : ''} fa`;
 if (diffDays < 30) return `${diffDays} giorno${diffDays !== 1 ? 'i' : ''} fa`;
 
 return new Date(date).toLocaleDateString('it-IT');
}

module.exports = {
 // String utilities
 generateRandomString,
 generateSecureToken,
 hashString,
 sanitizeString,
 slugify,
 escapeHtml,
 
 // Validation utilities
 isValidEmail,
 isValidIPv4,
 isValidCIDR,
 isValidPort,
 isValidUUID,
 
 // Format utilities
 formatBytes,
 formatDuration,
 formatUptime,
 timeAgo,
 
 // Object utilities
 objectHash,
 deepClone,
 deepMerge,
 
 // Network utilities
 getClientIP,
 normalizeAddressConfig,
 addressConfigToString,
 
 // Database utilities
 buildSequelizeFilters,
 buildSequelizeOrder,
 calculateOffset,
 formatPaginatedResponse,
 
 // File utilities
 generateSafeFilename,
 
 // Array utilities
 normalizeTags,
 
 // Security utilities
 calculatePasswordStrength,
 
 // Async utilities
 delay,
 retryWithBackoff,
 
 // Classes
 RateLimiter,
 SimpleCache
};