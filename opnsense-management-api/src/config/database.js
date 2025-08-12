const { Sequelize } = require('sequelize');
const Redis = require('redis');
const logger = require('../utils/logger');

// PostgreSQL Configuration
const dbConfig = {
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT) || 5432,
  database: process.env.POSTGRES_DB || 'opnsense_mgmt',
  username: process.env.POSTGRES_USER || 'opnsense',
  password: process.env.POSTGRES_PASSWORD,
  dialect: 'postgres',
  dialectOptions: {
    ssl: process.env.POSTGRES_SSL === 'true' ? {
      require: true,
      rejectUnauthorized: false
    } : false,
    connectTimeout: 60000,
    requestTimeout: 60000,
  },
  pool: {
    max: 10,
    min: 0,
    acquire: 60000,
    idle: 10000,
  },
  logging: process.env.NODE_ENV === 'development' ? 
    (msg) => logger.debug(msg) : false,
  define: {
    timestamps: true,
    underscored: true,
    paranoid: true, // Soft deletes
  },
  timezone: '+00:00', // UTC
};

// Initialize Sequelize
const sequelize = new Sequelize(dbConfig);

// Redis Configuration
const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD,
  db: 0,
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
  keepAlive: 30000,
  connectTimeout: 10000,
  commandTimeout: 5000,
};

// Initialize Redis client
const redis = Redis.createClient(redisConfig);

redis.on('connect', () => {
  logger.info('Redis connected successfully');
});

redis.on('error', (err) => {
  logger.error('Redis connection error:', err);
});

redis.on('ready', () => {
  logger.info('Redis ready for operations');
});

redis.on('reconnecting', () => {
  logger.warn('Redis reconnecting...');
});

// Database connection test
const testDatabaseConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info('PostgreSQL connection established successfully');
    return true;
  } catch (error) {
    logger.error('Unable to connect to PostgreSQL:', error.message);
    return false;
  }
};

// Redis connection test
const testRedisConnection = async () => {
  try {
    if (!redis.isOpen) {
      await redis.connect();
    }
    await redis.ping();
    logger.info('Redis connection established successfully');
    return true;
  } catch (error) {
    logger.error('Unable to connect to Redis:', error.message);
    return false;
  }
};

// Initialize all database connections
const initializeDatabase = async () => {
  const dbConnected = await testDatabaseConnection();
  const redisConnected = await testRedisConnection();

  if (!dbConnected) {
    throw new Error('Failed to connect to PostgreSQL database');
  }

  if (!redisConnected) {
    logger.warn('Redis connection failed, caching will be disabled');
  }

  // Sync database models (only in development)
  if (process.env.NODE_ENV === 'development') {
    try {
      await sequelize.sync({ alter: true });
      logger.info('Database models synchronized');
    } catch (error) {
      logger.error('Database sync error:', error.message);
    }
  }

  return { sequelize, redis };
};

// Graceful shutdown
const closeConnections = async () => {
  try {
    if (redis.isOpen) {
      await redis.quit();
      logger.info('Redis connection closed');
    }
    
    await sequelize.close();
    logger.info('PostgreSQL connection closed');
  } catch (error) {
    logger.error('Error closing database connections:', error.message);
  }
};

// Cache helper functions
const cache = {
  async get(key) {
    try {
      if (!redis.isOpen) return null;
      const value = await redis.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Cache get error:', error.message);
      return null;
    }
  },

  async set(key, value, ttl = parseInt(process.env.REDIS_TTL) || 3600) {
    try {
      if (!redis.isOpen) return false;
      await redis.setEx(key, ttl, JSON.stringify(value));
      return true;
    } catch (error) {
      logger.error('Cache set error:', error.message);
      return false;
    }
  },

  async del(key) {
    try {
      if (!redis.isOpen) return false;
      await redis.del(key);
      return true;
    } catch (error) {
      logger.error('Cache delete error:', error.message);
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
      logger.error('Cache flush error:', error.message);
      return false;
    }
  }
};

module.exports = {
  sequelize,
  redis,
  cache,
  initializeDatabase,
  testDatabaseConnection,
  testRedisConnection,
  closeConnections,
  dbConfig,
  redisConfig
};