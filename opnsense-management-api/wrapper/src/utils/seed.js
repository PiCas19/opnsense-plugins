#!/usr/bin/env node

/**
 * Script per popolare database con dati iniziali
 */

const { initializeDatabase, testConnection } = require('../config/database');
const User = require('../models/User');
const Rule = require('../models/Rule');
const logger = require('../utils/logger');

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
    description: 'Block P2P Traffic',
    interface: 'wan',
    direction: 'in',
    action: 'block',
    protocol: 'tcp',
    source_config: {
      type: 'any'
    },
    destination_config: {
      type: 'any'
    },
    enabled: true,
    sequence: 150,
    log_enabled: true,
    category: 'policy',
    tags: ['p2p', 'bandwidth', 'policy'],
    risk_level: 'medium',
    business_justification: 'Block P2P traffic to preserve bandwidth',
    approval_status: 'approved',
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 giorni
    auto_disable_on_expiry: true
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
  },
  {
    description: 'Test Rule - Disabled',
    interface: 'dmz',
    direction: 'in',
    action: 'pass',
    protocol: 'icmp',
    source_config: {
      type: 'single',
      address: '10.0.0.1'
    },
    destination_config: {
      type: 'single',
      address: '192.168.216.50'
    },
    enabled: false,
    sequence: 999,
    log_enabled: true,
    category: 'testing',
    tags: ['test', 'icmp', 'disabled'],
    risk_level: 'low',
    business_justification: 'Test rule for development purposes',
    approval_status: 'draft'
  }
];

async function seedDatabase() {
  try {
    logger.info('Starting database seeding...');

    // Test connessione
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }

    // Inizializza database
    await initializeDatabase();

    // Controlla se esistono già dati
    const userCount = await User.count();
    if (userCount > 0) {
      logger.info(`Database already contains ${userCount} users, skipping user seed`);
    } else {
      // Crea utenti
      logger.info('Creating seed users...');
      const users = [];
      for (const userData of seedUsers) {
        const user = await User.create(userData);
        users.push(user);
        logger.info(`✅ Created user: ${user.username} (${user.role}) - ${user.is_active ? 'Active' : 'Inactive'}`);
      }
    }

    // Controlla regole esistenti
    const ruleCount = await Rule.count();
    if (ruleCount > 0) {
      logger.info(`Database already contains ${ruleCount} rules, skipping rule seed`);
    } else {
      // Crea regole (assegna al primo admin)
      const adminUser = await User.findOne({ where: { role: 'admin' } });
      if (adminUser) {
        logger.info('Creating seed rules...');
        for (const ruleData of seedRules) {
          const rule = await Rule.create({
            ...ruleData,
            created_by: adminUser.id
          });
          logger.info(`✅ Created rule: ${rule.description} (${rule.action}) - ${rule.enabled ? 'Enabled' : 'Disabled'}`);
        }
      } else {
        logger.warn('No admin user found, skipping rule creation');
      }
    }

    // Statistiche finali
    const finalUserCount = await User.count();
    const finalRuleCount = await Rule.count();
    const activeUsers = await User.count({ where: { is_active: true } });
    const activeRules = await Rule.count({ where: { enabled: true } });

    logger.info('Database seeding completed successfully');
    logger.info('\n📊 Final Statistics:');
    logger.info(`   Users: ${finalUserCount} total, ${activeUsers} active`);
    logger.info(`   Rules: ${finalRuleCount} total, ${activeRules} enabled`);
    
    logger.info('\n👥 Default users created:');
    logger.info('   - admin / Admin123! (Administrator)');
    logger.info('   - operator / Operator123! (Operator)');
    logger.info('   - viewer / Viewer123! (Viewer)');
    logger.info('   - testuser / Test123! (Operator - Inactive)');
    
    logger.info('\n⚠️  IMPORTANT: Change default passwords in production!');

  } catch (error) {
    logger.error('Seeding failed:', error);
    throw error;
  }
}

async function resetDatabase() {
  try {
    logger.info('Resetting database...');

    // Inizializza connessione
    await testConnection();
    await initializeDatabase();

    // Elimina tutti i dati
    await Rule.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });

    logger.info('Database reset completed');

    // Re-seed
    await seedDatabase();

  } catch (error) {
    logger.error('Reset failed:', error);
    throw error;
  }
}

async function addSampleData() {
  try {
    logger.info('Adding additional sample data...');

    const adminUser = await User.findOne({ where: { role: 'admin' } });
    if (!adminUser) {
      throw new Error('Admin user not found');
    }

    // Aggiungi regole aggiuntive con statistiche simulate
    const additionalRules = [
      {
        description: 'Allow NTP Traffic',
        interface: 'lan',
        direction: 'out',
        action: 'pass',
        protocol: 'udp',
        source_config: { type: 'network', network: '192.168.1.0/24' },
        destination_config: { type: 'any', port: 123 },
        enabled: true,
        sequence: 700,
        log_enabled: false,
        category: 'infrastructure',
        tags: ['ntp', 'time', 'infrastructure'],
        risk_level: 'low',
        business_justification: 'Network Time Protocol for time synchronization',
        approval_status: 'approved',
        created_by: adminUser.id,
        statistics: {
          total_hits: 1250,
          total_bytes: 15600,
          total_packets: 1250,
          daily: {
            [new Date().toISOString().split('T')[0]]: {
              hits: 45,
              bytes: 540,
              packets: 45,
              allows: 45,
              blocks: 0
            }
          }
        },
        hit_count: 1250,
        first_matched_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        last_matched_at: new Date()
      }
    ];

    for (const ruleData of additionalRules) {
      const rule = await Rule.create(ruleData);
      logger.info(`✅ Created additional rule: ${rule.description}`);
    }

    logger.info('Sample data added successfully');

  } catch (error) {
    logger.error('Failed to add sample data:', error);
    throw error;
  }
}

// CLI interface
async function main() {
  const command = process.argv[2];

  try {
    switch (command) {
      case 'reset':
        await resetDatabase();
        break;
      case 'sample':
        await addSampleData();
        break;
      case 'help':
        console.log('\nOPNsense API Database Seeding Tool\n');
        console.log('Usage: npm run seed [command]\n');
        console.log('Commands:');
        console.log('  (no command)  Seed database with initial data');
        console.log('  reset         Reset and re-seed database');
        console.log('  sample        Add additional sample data');
        console.log('  help          Show this help\n');
        process.exit(0);
        break;
      default:
        await seedDatabase();
        break;
    }
    
    process.exit(0);
  } catch (error) {
    logger.error('Command failed:', error);
    process.exit(1);
  }
}

// Esegui se script chiamato direttamente
if (require.main === module) {
  main();
}

module.exports = { 
  seedDatabase, 
  resetDatabase,
  addSampleData,
  seedUsers,
  seedRules
};