const { Sequelize } = require('sequelize');
const path = require('path');
const logger = require('../utils/logger');

// Configurazione database
const config = {
  development: {
    dialect: 'sqlite',
    storage: path.join(process.cwd(), 'data', 'database.sqlite'),
    logging: (msg) => logger.debug('SQL:', msg),
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    }
  },
  test: {
    dialect: 'sqlite',
    storage: ':memory:',
    logging: false,
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    }
  },
  production: {
    dialect: process.env.DB_DIALECT || 'sqlite',
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'opnsense_api',
    username: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    storage: process.env.DB_DIALECT === 'sqlite' 
      ? path.join(process.cwd(), 'data', 'database.sqlite') 
      : undefined,
    logging: process.env.SQL_LOGGING === 'true' 
      ? (msg) => logger.debug('SQL:', msg) 
      : false,
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    },
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
};

const env = process.env.NODE_ENV || 'development';
const dbConfig = config[env];

// Crea istanza Sequelize
const sequelize = new Sequelize(dbConfig);

// Test connessione
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info('Database connection established successfully', {
      dialect: dbConfig.dialect,
      database: dbConfig.database || dbConfig.storage
    });
    return true;
  } catch (error) {
    logger.error('Unable to connect to the database:', error);
    return false;
  }
};

// Inizializza database e modelli
const initializeDatabase = async () => {
  try {
    // Importa modelli
    const User = require('../models/User');
    const Rule = require('../models/Rule');

    // Definisci associazioni
    User.associate({ Rule });
    Rule.associate({ User });

    // Sincronizza database
    if (env === 'development' || env === 'test') {
      await sequelize.sync({ alter: true });
      logger.info('Database synchronized successfully');
    } else {
      await sequelize.sync();
      logger.info('Database checked successfully');
    }

    return true;
  } catch (error) {
    logger.error('Failed to initialize database:', error);
    throw error;
  }
};

// Graceful shutdown
const closeDatabase = async () => {
  try {
    await sequelize.close();
    logger.info('Database connection closed');
  } catch (error) {
    logger.error('Error closing database connection:', error);
  }
};

module.exports = {
  sequelize,
  testConnection,
  initializeDatabase,
  closeDatabase
};