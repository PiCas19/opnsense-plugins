#!/usr/bin/env node

/**
 * Script per migrazione database
 */

const path = require('path');
const fs = require('fs');
const { initializeDatabase, testConnection, sequelize } = require('../config/database');
const logger = require('../utils/logger');

// Assicurati che la cartella data esista
const dataDir = path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  logger.info('Created data directory');
}

// Assicurati che la cartella logs esista
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
  logger.info('Created logs directory');
}

async function migrate() {
  try {
    logger.info('Starting database migration...');

    // Test connessione
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }

    // Inizializza database e modelli
    await initializeDatabase();

    // Verifica tabelle create
    const queryInterface = sequelize.getQueryInterface();
    const tables = await queryInterface.showAllTables();
    
    logger.info('Database tables:', tables);
    
    // Verifica indici
    for (const table of tables) {
      try {
        const indexes = await queryInterface.showIndex(table);
        logger.info(`Indexes for ${table}:`, indexes.length);
      } catch (error) {
        logger.warn(`Could not get indexes for ${table}:`, error.message);
      }
    }

    logger.info('Database migration completed successfully');
    process.exit(0);

  } catch (error) {
    logger.error('Migration failed:', error);
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
    await sequelize.drop();
    logger.info('All tables dropped');

    logger.info('Database rollback completed successfully');
    process.exit(0);

  } catch (error) {
    logger.error('Rollback failed:', error);
    process.exit(1);
  }
}

async function status() {
  try {
    logger.info('Checking database status...');
    
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }

    // Importa modelli per statistiche
    const User = require('../models/User');
    const Rule = require('../models/Rule');

    const userCount = await User.count();
    const ruleCount = await Rule.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const activeRules = await Rule.count({ where: { enabled: true } });

    logger.info('Database Status:', {
      total_users: userCount,
      active_users: activeUsers,
      total_rules: ruleCount,
      active_rules: activeRules,
      database_file: process.env.NODE_ENV === 'development' ? 
        path.join(process.cwd(), 'data', 'database.sqlite') : 
        'Database configured'
    });

    process.exit(0);

  } catch (error) {
    logger.error('Status check failed:', error);
    process.exit(1);
  }
}

// CLI interface
async function main() {
  const command = process.argv[2];

  try {
    switch (command) {
      case 'rollback':
        await rollback();
        break;
      case 'status':
        await status();
        break;
      case 'help':
        console.log('\nOPNsense API Database Migration Tool\n');
        console.log('Usage: npm run migrate [command]\n');
        console.log('Commands:');
        console.log('  (no command)  Run database migration');
        console.log('  rollback      Drop all tables');
        console.log('  status        Show database status');
        console.log('  help          Show this help\n');
        process.exit(0);
        break;
      default:
        await migrate();
        break;
    }
  } catch (error) {
    logger.error('Command failed:', error);
    process.exit(1);
  }
}

// Esegui se script chiamato direttamente
if (require.main === module) {
  main();
}

module.exports = { migrate, rollback, status };