// src/config/database.js
const { Sequelize } = require('sequelize');
const Redis = require('redis');
const logger = require('../utils/logger');

// =====================
// PostgreSQL
// =====================
const dbConfig = {
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT, 10) || 5432,
  database: process.env.POSTGRES_DB || 'opnsense_mgmt',
  username: process.env.POSTGRES_USER || 'opnsense',
  password: process.env.POSTGRES_PASSWORD,
  dialect: 'postgres',
  dialectOptions: {
    ssl:
      process.env.POSTGRES_SSL === 'true'
        ? { require: true, rejectUnauthorized: false }
        : false,
    connectTimeout: 60000,
    requestTimeout: 60000,
  },
  pool: {
    max: 10,
    min: 0,
    acquire: 60000,
    idle: 10000,
  },
  logging:
    process.env.NODE_ENV === 'development'
      ? (msg) => logger.debug(msg)
      : false,
  define: {
    timestamps: true,
    underscored: true,
    paranoid: true, // Soft deletes
  },
  timezone: '+00:00', // UTC
};

const sequelize = new Sequelize(dbConfig);

// =====================
// Redis (node-redis v4)
// =====================
const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
const REDIS_PORT = parseInt(process.env.REDIS_PORT, 10) || 6379;
const REDIS_DB = Number.isInteger(parseInt(process.env.REDIS_DB, 10))
  ? parseInt(process.env.REDIS_DB, 10)
  : 0;

const redisUrlFromParts = () => {
  if (process.env.REDIS_PASSWORD && process.env.REDIS_PASSWORD.length > 0) {
    return `redis://:${encodeURIComponent(process.env.REDIS_PASSWORD)}@${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}`;
  }
  return `redis://${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}`;
};

const REDIS_URL = process.env.REDIS_URL || redisUrlFromParts();

const redis = Redis.createClient({
  url: REDIS_URL,
  socket: {
    // tempi ragionevoli per ambienti docker
    connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT || '10000', 10),
    keepAlive: parseInt(process.env.REDIS_KEEP_ALIVE || '30000', 10),
    // backoff esponenziale con cap a 15s
    reconnectStrategy: (retries) => {
      const delay = Math.min(1000 * 2 ** retries, 15000);
      // logga in modo sobrio
      if (retries % 3 === 0) {
        logger.warn(`Redis reconnect attempt #${retries + 1} in ${delay}ms`);
      }
      return delay;
    },
  },
  // database index viene preso dall'URL (…/<db>)
});

// Eventi
redis.on('connect', () => {
  logger.info('Redis TCP connection established');
});
redis.on('ready', () => {
  logger.info('Redis ready for operations');
});
redis.on('end', () => {
  logger.warn('Redis connection closed');
});
redis.on('error', (err) => {
  // Evita spam: logga codice e poche info utili
  logger.error('Redis connection error:', { code: err.code, stack: err.stack });
});

// =====================
// Test connessioni
// =====================
const testDatabaseConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info('PostgreSQL connection established successfully');
    return true;
  } catch (error) {
    logger.error('Unable to connect to PostgreSQL:', {
      message: error.message,
    });
    return false;
  }
};

const testRedisConnection = async () => {
  try {
    if (!redis.isOpen) {
      await redis.connect();
    }
    await redis.ping();
    logger.info('Redis connection established successfully');
    return true;
  } catch (error) {
    // Non far fallire l’app: restituisci false e lascia warning in initializeDatabase
    logger.error('Unable to connect to Redis:', {
      message: error.message,
      code: error.code,
      host: REDIS_HOST,
      port: REDIS_PORT,
    });
    return false;
  }
};

// =====================
// Bootstrap / Shutdown
// =====================
const initializeDatabase = async () => {
  const dbConnected = await testDatabaseConnection();
  const redisConnected = await testRedisConnection();

  if (!dbConnected) {
    throw new Error('Failed to connect to PostgreSQL database');
  }

  if (!redisConnected) {
    logger.warn('Redis connection failed, caching will be disabled');
  }

  if (process.env.NODE_ENV === 'development') {
    try {
      await sequelize.sync({ alter: true });
      logger.info('Database models synchronized');
    } catch (error) {
      logger.error('Database sync error:', { message: error.message });
    }
  }

  return { sequelize, redis };
};

const closeConnections = async () => {
  try {
    if (redis.isOpen) {
      await redis.quit();
      logger.info('Redis connection closed');
    }
  } catch (error) {
    logger.error('Error closing Redis connection:', { message: error.message });
  }

  try {
    await sequelize.close();
    logger.info('PostgreSQL connection closed');
  } catch (error) {
    logger.error('Error closing PostgreSQL connection:', {
      message: error.message,
    });
  }
};

// =====================
// Cache helper (best-effort)
// =====================
const cache = {
  async get(key) {
    try {
      if (!redis.isOpen) return null;
      const value = await redis.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Cache get error:', { message: error.message });
      return null;
    }
  },

  async set(key, value, ttl = parseInt(process.env.REDIS_TTL || '3600', 10)) {
    try {
      if (!redis.isOpen) return false;
      await redis.setEx(key, ttl, JSON.stringify(value));
      return true;
    } catch (error) {
      logger.error('Cache set error:', { message: error.message });
      return false;
    }
  },

  async del(key) {
    try {
      if (!redis.isOpen) return false;
      await redis.del(key);
      return true;
    } catch (error) {
      logger.error('Cache delete error:', { message: error.message });
      return false;
    }
  },

  async flush() {
    try {
      if (!redis.isOpen) return false;
      await redis.flushDb();
      logger.info('Redis cache flushed');
      return true;
    } catch (error) {
      logger.error('Cache flush error:', { message: error.message });
      return false;
    }
  },
};

// Esportazioni
module.exports = {
  sequelize,
  redis,
  cache,
  initializeDatabase,
  testDatabaseConnection,
  testRedisConnection,
  closeConnections,
  dbConfig,
  redisConfig: { url: REDIS_URL, host: REDIS_HOST, port: REDIS_PORT, db: REDIS_DB },
};