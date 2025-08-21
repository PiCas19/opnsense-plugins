#!/usr/bin/env node

/**
 * Script per migrazione database
 */

const path = require('path');
const fs = require('fs');

// Assicurati che le cartelle esistano PRIMA di inizializzare il logger
const dataDir = path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  console.log('Created data directory');
}

const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
  console.log('Created logs directory');
}

// DOPO aver creato le cartelle, importa il logger
let logger;
try {
  logger = require('./logger');
  logger.info('Logger initialized successfully');
} catch (error) {
  // Fallback console logger se winston non funziona
  logger = {
    info: (...args) => console.log('INFO:', ...args),
    error: (...args) => console.error('ERROR:', ...args),
    warn: (...args) => console.warn('WARN:', ...args),
    debug: (...args) => console.log('DEBUG:', ...args)
  };
  console.log('Using fallback console logger');
}

const { initializeDatabase, testConnection, sequelize } = require('../config/database');

async function migrate() {
  try {
    logger.info('Starting database migration...');

    // Test connessione
    logger.info('Testing database connection...');
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }
    logger.info('Database connection successful');

    // Inizializza database e modelli
    logger.info('Initializing database and models...');
    await initializeDatabase();
    logger.info('Database and models initialized');

    // Verifica tabelle create
    try {
      const queryInterface = sequelize.getQueryInterface();
      const tables = await queryInterface.showAllTables();
      
      logger.info('Database tables created:', tables);
      
      // Verifica indici
      for (const table of tables) {
        try {
          const indexes = await queryInterface.showIndex(table);
          logger.info(`Indexes for ${table}: ${indexes.length} found`);
        } catch (error) {
          logger.warn(`Could not get indexes for ${table}: ${error.message}`);
        }
      }
    } catch (error) {
      logger.warn('Could not verify tables:', error.message);
    }

    logger.info('Database migration completed successfully');
    console.log('\nMigration completed! You can now run: npm run seed');
    process.exit(0);

  } catch (error) {
    logger.error('Migration failed:', error);
    console.error('\nMigration failed:', error.message);
    process.exit(1);
  }
}

async function rollback() {
  try {
    logger.info('Starting database rollback...');
    
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }

    // Drop all tables
    logger.info('Dropping all tables...');
    await sequelize.drop();
    logger.info('All tables dropped');

    logger.info('Database rollback completed successfully');
    console.log('\nRollback completed!');
    process.exit(0);

  } catch (error) {
    logger.error('Rollback failed:', error);
    console.error('\nRollback failed:', error.message);
    process.exit(1);
  }
}

async function status() {
  try {
    logger.info('🔍 Checking database status...');
    
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }

    // Importa modelli per statistiche
    let User, Rule;
    try {
      User = require('../models/User');
      Rule = require('../models/Rule');
    } catch (error) {
      logger.warn('Models not available, skipping detailed stats');
      console.log('Database Status: Connected, but models not initialized');
      process.exit(0);
    }

    const userCount = await User.count();
    const ruleCount = await Rule.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const activeRules = await Rule.count({ where: { enabled: true } });

    const status = {
      total_users: userCount,
      active_users: activeUsers,
      total_rules: ruleCount,
      active_rules: activeRules,
      database_file: process.env.NODE_ENV === 'development' ? 
        path.join(process.cwd(), 'data', 'database.sqlite') : 
        'Database configured'
    };

    logger.info('Database Status:', status);
    
    console.log('\nDatabase Status:');
    console.log(`   Users: ${userCount} total, ${activeUsers} active`);
    console.log(`   Rules: ${ruleCount} total, ${activeRules} enabled`);
    console.log(`   Database: ${status.database_file}`);

    process.exit(0);

  } catch (error) {
    logger.error('Status check failed:', error);
    console.error('\nStatus check failed:', error.message);
    process.exit(1);
  }
}

async function clean() {
  try {
    logger.info('Cleaning database files...');
    
    const dbFile = path.join(process.cwd(), 'data', 'database.sqlite');
    if (fs.existsSync(dbFile)) {
      fs.unlinkSync(dbFile);
      logger.info('Database file removed');
    }
    
    logger.info('Clean completed');
    console.log('\nDatabase files cleaned!');
    process.exit(0);
    
  } catch (error) {
    logger.error('Clean failed:', error);
    console.error('\nClean failed:', error.message);
    process.exit(1);
  }
}

// CLI interface
async function main() {
  const command = process.argv[2];

  // Banner
  console.log('\nOPNsense API Database Migration Tool\n');

  try {
    switch (command) {
      case 'rollback':
        await rollback();
        break;
      case 'status':
        await status();
        break;
      case 'clean':
        await clean();
        break;
      case 'help':
        console.log('Usage: npm run migrate [command]\n');
        console.log('Commands:');
        console.log('  (no command)  Run database migration');
        console.log('  rollback      Drop all tables');
        console.log('  status        Show database status');
        console.log('  clean         Remove database files');
        console.log('  help          Show this help\n');
        console.log('Examples:');
        console.log('  npm run migrate         # Create tables');
        console.log('  npm run migrate status  # Check status');
        console.log('  npm run migrate clean   # Clean database\n');
        process.exit(0);
        break;
      default:
        await migrate();
        break;
    }
  } catch (error) {
    logger.error('Command failed:', error);
    console.error('\nCommand failed:', error.message);
    console.error('\nTry running: npm run migrate help');
    process.exit(1);
  }
}

// Esegui se script chiamato direttamente
if (require.main === module) {
  main();
}

module.exports = { migrate, rollback, status, clean };