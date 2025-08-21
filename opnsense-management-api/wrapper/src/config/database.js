const { Sequelize } = require('sequelize');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');
const { getEnv } = require('../utils/env');

// Assicurati che la directory data esista
const dataDir = path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  console.log('Created data directory');
}

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
    },
    // Configurazioni SQLite specifiche per foreign keys
    dialectOptions: {
      // Disabilita foreign key constraints durante la sincronizzazione
      foreignKeys: false
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
    },
    dialectOptions: {
      foreignKeys: false
    }
  },
  production: {
    dialect: getEnv('DB_DIALECT', 'sqlite'),
    host: getEnv('DB_HOST', 'localhost'),
    port: parseInt(getEnv('DB_PORT', '5432')),
    database: getEnv('DB_NAME', 'opnsense_api'),
    username: getEnv('DB_USER', 'postgres'),
    password: getEnv('DB_PASSWORD', ''),
    storage: getEnv('DB_DIALECT', 'sqlite') === 'sqlite'
      ? path.join(process.cwd(), 'data', 'database.sqlite')
      : undefined,
    logging: getEnv('SQL_LOGGING', 'false') === 'true'
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
    },
    dialectOptions: {
      foreignKeys: false
    }
  }
};

const env = getEnv('NODE_ENV', 'development');
const dbConfig = config[env];

console.log(`Database environment: ${env}`);

// Crea istanza Sequelize
const sequelize = new Sequelize(dbConfig);

// Test connessione
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info('Database connection established successfully', {
      dialect: dbConfig.dialect,
      database: dbConfig.database || dbConfig.storage,
      environment: env
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
    console.log('Initializing database...');
    
    // Test connessione prima
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Cannot connect to database');
    }

    // Per SQLite, abilita foreign keys dopo la connessione
    if (dbConfig.dialect === 'sqlite') {
      await sequelize.query('PRAGMA foreign_keys = OFF;');
      console.log('Foreign keys temporarily disabled for setup');
    }

    // Importa modelli
    console.log('Loading models...');
    const User = require('../models/User');
    const Rule = require('../models/Rule');

    // Verifica che i modelli siano stati caricati
    if (!User || !Rule) {
      throw new Error('Failed to load models');
    }

    console.log('Setting up associations...');
    
    // Definisci associazioni solo se i metodi esistono
    if (typeof User.associate === 'function') {
      User.associate({ Rule });
    }
    if (typeof Rule.associate === 'function') {
      Rule.associate({ User });
    }

    console.log('Synchronizing database...');

    // Sincronizza database con strategia più sicura
    if (env === 'development') {
      // In development, drop e ricrea solo se necessario
      await sequelize.sync({ 
        force: false,  // Cambiato da true a false per evitare perdita dati
        alter: true    // Altera le tabelle esistenti invece di ricrearle
      });
    } else if (env === 'test') {
      // In test, sempre force per clean state
      await sequelize.sync({ force: true });
    } else {
      // In production, solo sync senza modifiche strutturali
      await sequelize.sync({ force: false, alter: false });
    }

    // Riabilita foreign keys per SQLite
    if (dbConfig.dialect === 'sqlite') {
      await sequelize.query('PRAGMA foreign_keys = ON;');
      console.log('Foreign keys re-enabled');
    }

    logger.info('Database synchronized successfully', {
      environment: env,
      dialect: dbConfig.dialect
    });

    console.log('Database initialization completed');
    return true;

  } catch (error) {
    logger.error('Failed to initialize database:', error);
    console.error('Database initialization failed:', error.message);
    
    // In caso di errore, prova a ricreare il database da zero
    if (env === 'development' && dbConfig.dialect === 'sqlite') {
      console.log('Attempting to recreate database...');
      try {
        await sequelize.query('PRAGMA foreign_keys = OFF;');
        await sequelize.sync({ force: true });
        await sequelize.query('PRAGMA foreign_keys = ON;');
        console.log('Database recreated successfully');
        return true;
      } catch (recreateError) {
        console.error('Failed to recreate database:', recreateError.message);
      }
    }
    
    throw error;
  }
};

// Graceful shutdown
const closeDatabase = async () => {
  try {
    await sequelize.close();
    logger.info('Database connection closed');
    console.log('Database connection closed');
  } catch (error) {
    logger.error('Error closing database connection:', error);
    console.error('Error closing database:', error.message);
  }
};

// Reset database (per sviluppo)
const resetDatabase = async () => {
  if (env !== 'development') {
    throw new Error('Database reset is only allowed in development environment');
  }

  try {
    console.log('Resetting database...');
    await sequelize.query('PRAGMA foreign_keys = OFF;');
    await sequelize.sync({ force: true });
    await sequelize.query('PRAGMA foreign_keys = ON;');
    console.log('Database reset completed');
    return true;
  } catch (error) {
    console.error('Database reset failed:', error.message);
    throw error;
  }
};

module.exports = {
  sequelize,
  testConnection,
  initializeDatabase,
  closeDatabase,
  resetDatabase
};