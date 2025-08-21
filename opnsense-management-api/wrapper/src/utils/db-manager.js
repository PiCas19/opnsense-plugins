// scripts/db-manager.js
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const command = process.argv[2];
const dbPath = path.join(process.cwd(), 'data', 'database.sqlite');

// Funzione per eseguire query SQL
function runQuery(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

// Funzione per ottenere risultati
function getQuery(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Schema del database
const createTablesSQL = {
  users: `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      first_name VARCHAR(50),
      last_name VARCHAR(50),
      role VARCHAR(20) DEFAULT 'viewer',
      is_active BOOLEAN DEFAULT 1,
      login_attempts INTEGER DEFAULT 0,
      locked_until DATETIME,
      last_login DATETIME,
      login_ip VARCHAR(45),
      user_agent TEXT,
      last_activity DATETIME,
      preferences TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME
    )
  `,
  rules: `
    CREATE TABLE IF NOT EXISTS rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid VARCHAR(36) NOT NULL UNIQUE,
      description TEXT NOT NULL,
      interface VARCHAR(20) NOT NULL,
      action VARCHAR(10) NOT NULL,
      enabled BOOLEAN DEFAULT 1,
      source_config TEXT,
      destination_config TEXT,
      protocol VARCHAR(10) DEFAULT 'any',
      log_enabled BOOLEAN DEFAULT 0,
      sequence INTEGER DEFAULT 1000,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      deleted_at DATETIME,
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `
};

// Dati di default
const defaultData = {
  users: `
    INSERT OR IGNORE INTO users (
      username, email, password, first_name, last_name, role, is_active
    ) VALUES (
      'admin', 
      'admin@localhost', 
      '$2b$10$rQH.Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Qf8Q', 
      'Administrator', 
      'System', 
      'admin', 
      1
    )
  `
};

async function initializeDatabase() {
  return new Promise((resolve, reject) => {
    // Assicurati che la directory data esista
    const dataDir = path.dirname(dbPath);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
      console.log('Created data directory');
    }

    const db = new sqlite3.Database(dbPath, async (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
        reject(err);
        return;
      }

      try {
        console.log('Creating tables...');
        
        // Disabilita foreign keys temporaneamente
        await runQuery(db, 'PRAGMA foreign_keys = OFF');
        
        // Crea tabelle
        for (const [tableName, sql] of Object.entries(createTablesSQL)) {
          console.log(`Creating table: ${tableName}`);
          await runQuery(db, sql);
        }

        // Inserisci dati di default
        console.log('Inserting default data...');
        for (const [tableName, sql] of Object.entries(defaultData)) {
          await runQuery(db, sql);
        }

        // Riabilita foreign keys
        await runQuery(db, 'PRAGMA foreign_keys = ON');

        console.log('Database initialized successfully');
        
        db.close((err) => {
          if (err) reject(err);
          else resolve();
        });
        
      } catch (error) {
        console.error('Error initializing database:', error.message);
        db.close();
        reject(error);
      }
    });
  });
}

async function resetDatabase() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, async (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
        reject(err);
        return;
      }

      try {
        console.log('Dropping tables...');
        
        await runQuery(db, 'PRAGMA foreign_keys = OFF');
        await runQuery(db, 'DROP TABLE IF EXISTS rules');
        await runQuery(db, 'DROP TABLE IF EXISTS users');
        
        console.log('🔧 Recreating tables...');
        
        // Ricrea tabelle
        for (const [tableName, sql] of Object.entries(createTablesSQL)) {
          console.log(`Creating table: ${tableName}`);
          await runQuery(db, sql);
        }

        // Inserisci dati di default
        console.log('Inserting default data...');
        for (const [tableName, sql] of Object.entries(defaultData)) {
          await runQuery(db, sql);
        }

        await runQuery(db, 'PRAGMA foreign_keys = ON');

        console.log('Database reset successfully');
        
        db.close((err) => {
          if (err) reject(err);
          else resolve();
        });
        
      } catch (error) {
        console.error('Error resetting database:', error.message);
        db.close();
        reject(error);
      }
    });
  });
}

async function checkTables() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, async (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
        reject(err);
        return;
      }

      try {
        const tables = await getQuery(db, `
          SELECT name FROM sqlite_master 
          WHERE type='table' AND name NOT LIKE 'sqlite_%'
          ORDER BY name
        `);

        console.log('Database tables:');
        for (const table of tables) {
          const count = await getQuery(db, `SELECT COUNT(*) as count FROM ${table.name}`);
          console.log(`   ${table.name}: ${count[0].count} records`);
        }

        db.close((err) => {
          if (err) reject(err);
          else resolve();
        });
        
      } catch (error) {
        console.error('Error checking tables:', error.message);
        db.close();
        reject(error);
      }
    });
  });
}

async function main() {
  console.log('Database Manager');
  console.log('==================');

  try {
    switch (command) {
      case 'init':
        console.log('Initializing database...');
        await initializeDatabase();
        break;

      case 'reset':
        console.log('Resetting database...');
        if (!fs.existsSync(dbPath)) {
          console.log('Database file does not exist');
          break;
        }
        await resetDatabase();
        break;

      case 'drop':
        console.log('Dropping database...');
        if (fs.existsSync(dbPath)) {
          fs.unlinkSync(dbPath);
          console.log('Database file deleted');
        } else {
          console.log('Database file does not exist');
        }
        break;

      case 'recreate':
        console.log('Recreating database from scratch...');
        
        // Drop file
        if (fs.existsSync(dbPath)) {
          fs.unlinkSync(dbPath);
          console.log('Old database deleted');
        }
        
        // Recreate
        await initializeDatabase();
        console.log('Database recreated successfully');
        break;

      case 'status':
        console.log('Checking database status...');
        if (fs.existsSync(dbPath)) {
          const stats = fs.statSync(dbPath);
          console.log(`Database exists (${stats.size} bytes)`);
          console.log(`   Created: ${stats.birthtime}`);
          console.log(`   Modified: ${stats.mtime}`);
          await checkTables();
        } else {
          console.log('Database file does not exist');
        }
        break;

      case 'tables':
        console.log('Checking database tables...');
        if (fs.existsSync(dbPath)) {
          await checkTables();
        } else {
          console.log('Database file does not exist');
        }
        break;

      default:
        console.log('Available commands:');
        console.log('  init     - Initialize database');
        console.log('  reset    - Reset database (development only)');
        console.log('  drop     - Drop database file');
        console.log('  recreate - Drop and recreate database');
        console.log('  status   - Check database status');
        console.log('  tables   - List tables and record counts');
        console.log('');
        console.log('Usage: node scripts/db-manager.js <command>');
        break;
    }

  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();