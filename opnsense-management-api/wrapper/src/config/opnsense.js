// config/opnsense.js - Configurazione semplificata senza gestione certificati SSL
const { getEnv, requireEnv } = require('../utils/env');

// Verifica variabili richieste
requireEnv(['OPNSENSE_HOST', 'OPNSENSE_API_KEY', 'OPNSENSE_API_SECRET']);

const config = {
  host: getEnv('OPNSENSE_HOST'),
  apiKey: getEnv('OPNSENSE_API_KEY'),
  apiSecret: getEnv('OPNSENSE_API_SECRET'),
  verifySSL: getEnv('OPNSENSE_VERIFY_SSL', 'false') === 'true',
  timeout: parseInt(getEnv('OPNSENSE_TIMEOUT', '30000'))
};

// Validazione configurazione
const validateConfig = () => {
  // Verifica formato host
  if (!config.host.startsWith('http://') && !config.host.startsWith('https://')) {
    config.host = `https://${config.host}`;
  }

  // Rimuovi trailing slash
  config.host = config.host.replace(/\/$/, '');
 
  // Log configurazione
  console.log('OPNsense Configuration:');
  console.log(`   - Host: ${config.host}`);
  console.log(`   - SSL Verification: ${config.verifySSL ? 'ENABLED' : 'DISABLED'}`);
  console.log(`   - Timeout: ${config.timeout}ms`);
  console.log(`   - Has Credentials: ${!!(config.apiKey && config.apiSecret)}`);

  if (config.verifySSL) {
    console.warn('SSL verification is ENABLED');
    console.warn('   Per certificati auto-firmati, imposta OPNSENSE_VERIFY_SSL=false nel .env');
  } else {
    console.log('SSL verification DISABLED - Adatto per certificati auto-firmati');
  }
};

validateConfig();

module.exports = config;