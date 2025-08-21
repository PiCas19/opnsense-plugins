// src/utils/db-manager.js
const { sequelize, initializeDatabase, resetDatabase, closeDatabase } = require('../config/database');
const User = require('../models/User');
const Rule = require('../models/Rule');
const path = require('path');
const fs = require('fs');

const command = process.argv[2];

// Dati seed utenti
const seedUsers = [
  {
    username: 'admin',
    email: 'admin@example.com',
    password: 'Admin123!',
    first_name: 'System',
    last_name: 'Administrator',
    role: 'admin',
    is_active: true,
    email_verified: true,
    preferences: {
      theme: 'dark',
      language: 'it',
      timezone: 'Europe/Rome',
      notifications: {
        email: true,
        browser: true,
        critical_only: false
      }
    }
  },
  {
    username: 'operator',
    email: 'operator@example.com', 
    password: 'Operator123!',
    first_name: 'Network',
    last_name: 'Operator',
    role: 'operator',
    is_active: true,
    email_verified: true,
    preferences: {
      theme: 'light',
      language: 'it',
      timezone: 'Europe/Rome',
      notifications: {
        email: true,
        browser: false,
        critical_only: true
      }
    }
  },
  {
    username: 'viewer',
    email: 'viewer@example.com',
    password: 'Viewer123!',
    first_name: 'Read',
    last_name: 'Only',
    role: 'viewer',
    is_active: true,
    email_verified: true,
    preferences: {
      theme: 'light',
      language: 'it',
      timezone: 'Europe/Rome',
      notifications: {
        email: false,
        browser: false,
        critical_only: true
      }
    }
  },
  {
    username: 'testuser',
    email: 'test@example.com',
    password: 'Test123!',
    first_name: 'Test',
    last_name: 'User',
    role: 'operator',
    is_active: false,
    email_verified: false,
    preferences: {
      theme: 'light',
      language: 'en',
      timezone: 'UTC',
      notifications: {
        email: true,
        browser: true,
        critical_only: false
      }
    }
  }
];

// Dati seed regole
const seedRules = [
  {
    description: 'Block Malicious IPs',
    interface: 'wan',
    direction: 'in',
    action: 'block',
    protocol: 'any',
    source_config: {
      type: 'network',
      network: '192.168.100.0/24'
    },
    destination_config: {
      type: 'any'
    },
    enabled: true,
    sequence: 100,
    log_enabled: true,
    category: 'security',
    tags: ['malicious', 'block', 'security'],
    risk_level: 'high',
    business_justification: 'Block known malicious IP range from threat intelligence',
    approval_status: 'approved'
  },
  {
    description: 'Allow SSH Management',
    interface: 'lan',
    direction: 'in',
    action: 'pass',
    protocol: 'tcp',
    source_config: {
      type: 'network',
      network: '192.168.1.0/24'
    },
    destination_config: {
      type: 'single',
      address: '192.168.216.1',
      port: 22
    },
    enabled: true,
    sequence: 200,
    log_enabled: false,
    category: 'management',
    tags: ['ssh', 'management', 'internal'],
    risk_level: 'medium',
    business_justification: 'SSH access for network management from trusted LAN',
    approval_status: 'approved'
  },
  {
    description: 'Block Suspicious Port Scans',
    interface: 'wan',
    direction: 'in',
    action: 'reject',
    protocol: 'tcp',
    source_config: {
      type: 'any'
    },
    destination_config: {
      type: 'network',
      network: '192.168.216.0/24'
    },
    enabled: false,
    sequence: 300,
    log_enabled: true,
    category: 'security',
    tags: ['port-scan', 'intrusion', 'security'],
    risk_level: 'high',
    business_justification: 'Prevent port scanning attempts on internal network',
    approval_status: 'pending_review'
  },
  {
    description: 'Allow Web Traffic',
    interface: 'wan',
    direction: 'in',
    action: 'pass',
    protocol: 'tcp',
    source_config: {
      type: 'any'
    },
    destination_config: {
      type: 'single',
      address: '192.168.216.100',
      port: 80
    },
    enabled: true,
    sequence: 400,
    log_enabled: false,
    category: 'web',
    tags: ['http', 'web', 'public'],
    risk_level: 'low',
    business_justification: 'Public web server access for company website',
    approval_status: 'approved'
  },
  {
    description: 'Allow HTTPS Traffic',
    interface: 'wan',
    direction: 'in',
    action: 'pass',
    protocol: 'tcp',
    source_config: {
      type: 'any'
    },
    destination_config: {
      type: 'single',
      address: '192.168.216.100',
      port: 443
    },
    enabled: true,
    sequence: 500,
    log_enabled: false,
    category: 'web',
    tags: ['https', 'ssl', 'web', 'public'],
    risk_level: 'low',
    business_justification: 'Secure web server access for company website',
    approval_status: 'approved'
  },
  {
    description: 'Allow DNS Queries',
    interface: 'lan',
    direction: 'out',
    action: 'pass',
    protocol: 'udp',
    source_config: {
      type: 'network',
      network: '192.168.1.0/24'
    },
    destination_config: {
      type: 'any',
      port: 53
    },
    enabled: true,
    sequence: 600,
    log_enabled: false,
    category: 'infrastructure',
    tags: ['dns', 'infrastructure', 'outbound'],
    risk_level: 'low',
    business_justification: 'Allow DNS resolution for internal clients',
    approval_status: 'approved'
  }
];

async function seedData() {
  try {
    console.log('Seeding database with initial data...');

    // Controlla se esistono già utenti
    const userCount = await User.count();
    if (userCount > 0) {
      console.log(`Database already contains ${userCount} users, skipping user seed`);
    } else {
      // Crea utenti
      console.log('Creating seed users...');
      for (const userData of seedUsers) {
        const user = await User.create(userData);
        console.log(`Created user: ${user.username} (${user.role}) - ${user.is_active ? 'Active' : 'Inactive'}`);
      }
    }

    // Controlla regole esistenti
    const ruleCount = await Rule.count();
    if (ruleCount > 0) {
      console.log(`Database already contains ${ruleCount} rules, skipping rule seed`);
    } else {
      // Crea regole (assegna al primo admin)
      const adminUser = await User.findOne({ where: { role: 'admin' } });
      if (adminUser) {
        console.log('Creating seed rules...');
        for (const ruleData of seedRules) {
          const rule = await Rule.create({
            ...ruleData,
            created_by: adminUser.id
          });
          console.log(`Created rule: ${rule.description} (${rule.action}) - ${rule.enabled ? 'Enabled' : 'Disabled'}`);
        }
      } else {
        console.log('No admin user found, skipping rule creation');
      }
    }

    // Statistiche finali
    const finalUserCount = await User.count();
    const finalRuleCount = await Rule.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const activeRules = await Rule.count({ where: { enabled: true } });

    console.log('\nDatabase Statistics:');
    console.log(`   Users: ${finalUserCount} total, ${activeUsers} active`);
    console.log(`   Rules: ${finalRuleCount} total, ${activeRules} enabled`);
    
    console.log('\nDefault credentials:');
    console.log('   - admin / Admin123! (Administrator)');
    console.log('   - operator / Operator123! (Operator)');
    console.log('   - viewer / Viewer123! (Viewer)');
    console.log('   - testuser / Test123! (Operator - Inactive)');
    
    console.log('\nIMPORTANT: Change default passwords in production!');

  } catch (error) {
    console.error('Seeding failed:', error.message);
    throw error;
  }
}

async function clearData() {
  try {
    console.log('Clearing all data...');
    
    // Elimina tutti i dati (rispettando foreign keys)
    await Rule.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });

    console.log('All data cleared');

  } catch (error) {
    console.error('Error clearing data:', error.message);
    throw error;
  }
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

      case 'seed':
        console.log('Seeding database...');
        await initializeDatabase();
        await seedData();
        break;

      case 'reset':
        console.log('Resetting database...');
        if (typeof resetDatabase === 'function') {
          await resetDatabase();
        } else {
          // Fallback: clear data and reinitialize
          await initializeDatabase();
          await clearData();
          await seedData();
        }
        break;

      case 'drop':
        console.log('Dropping database...');
        const dbPath = path.join(process.cwd(), 'data', 'database.sqlite');
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
        const dbFile = path.join(process.cwd(), 'data', 'database.sqlite');
        if (fs.existsSync(dbFile)) {
          fs.unlinkSync(dbFile);
          console.log('Old database deleted');
        }
        
        // Recreate and seed
        await initializeDatabase();
        await seedData();
        console.log('Database recreated successfully');
        break;

      case 'clear':
        console.log('Clearing all data...');
        await clearData();
        break;

      case 'status':
        console.log('Checking database status...');
        try {
          // Prova a connettersi al database
          await sequelize.authenticate();
          console.log('Database connection successful');
          
          // Ottieni informazioni dal database
          const userCount = await User.count();
          const ruleCount = await Rule.count();
          console.log(`\nRecords:`);
          console.log(`   Users: ${userCount}`);
          console.log(`   Rules: ${ruleCount}`);
          
          // Prova a ottenere info sul file se è SQLite
          try {
            const dbConfig = sequelize.config;
            if (dbConfig.dialect === 'sqlite' && dbConfig.storage) {
              const dbPath = dbConfig.storage;
              console.log(`\nDatabase file: ${dbPath}`);
              
              if (fs.existsSync(dbPath)) {
                const stats = fs.statSync(dbPath);
                console.log(`   Size: ${stats.size} bytes`);
                console.log(`   Created: ${stats.birthtime}`);
                console.log(`   Modified: ${stats.mtime}`);
              }
            }
          } catch (fileError) {
            console.log('Could not get file info');
          }
          
        } catch (error) {
          console.error('Database connection failed:', error.message);
          
          // Prova percorsi comuni
          const possiblePaths = [
            path.join(process.cwd(), 'data', 'database.sqlite'),
            path.join(process.cwd(), 'database.sqlite'),
            path.join(process.cwd(), 'src', 'data', 'database.sqlite')
          ];
          
          console.log('\nChecking possible database locations:');
          for (const dbPath of possiblePaths) {
            if (fs.existsSync(dbPath)) {
              const stats = fs.statSync(dbPath);
              console.log(`Found: ${dbPath} (${stats.size} bytes)`);
            } else {
              console.log(`Not found: ${dbPath}`);
            }
          }
        }
        break;

      case 'stats':
        console.log('Getting database statistics...');
        try {
          await sequelize.authenticate();
          
          // Statistiche di base
          const userCount = await User.count();
          const ruleCount = await Rule.count();
          const activeUsers = await User.count({ where: { is_active: true } });
          const activeRules = await Rule.count({ where: { enabled: true } });
          
          console.log('\nDatabase Statistics:');
          console.log(`   Users: ${userCount} total, ${activeUsers} active`);
          console.log(`   Rules: ${ruleCount} total, ${activeRules} enabled`);
          
          // Prova a ottenere statistiche per ruolo (senza grouping)
          try {
            const adminCount = await User.count({ where: { role: 'admin' } });
            const operatorCount = await User.count({ where: { role: 'operator' } });
            const viewerCount = await User.count({ where: { role: 'viewer' } });
            
            console.log('\nUsers by Role:');
            if (adminCount > 0) console.log(`   admin: ${adminCount}`);
            if (operatorCount > 0) console.log(`   operator: ${operatorCount}`);
            if (viewerCount > 0) console.log(`   viewer: ${viewerCount}`);
          } catch (roleError) {
            console.log('Could not get role statistics');
          }
          
        } catch (error) {
          console.error('Cannot connect to database:', error.message);
        }
        break;

      default:
        console.log('Available commands:');
        console.log('  init     - Initialize database tables');
        console.log('  seed     - Initialize and seed with sample data');
        console.log('  reset    - Reset database and re-seed');
        console.log('  drop     - Drop database file');
        console.log('  recreate - Drop, recreate and seed database');
        console.log('  clear    - Clear all data (keep tables)');
        console.log('  status   - Check database status and stats');
        console.log('  stats    - Show detailed database statistics');
        console.log('');
        console.log('Usage: node scripts/db-manager.js <command>');
        console.log('   or: npm run db:<command>');
        break;
    }

  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  } finally {
    await closeDatabase();
    process.exit(0);
  }
}

main();