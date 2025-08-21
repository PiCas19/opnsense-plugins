const fs = require('fs');
const path = require('path');
const { getEnv, requireEnv } = require('../utils/env');

// Verifica variabili richieste
requireEnv(['OPNSENSE_HOST', 'OPNSENSE_API_KEY', 'OPNSENSE_API_SECRET']);

const config = {
  host: getEnv('OPNSENSE_HOST'),
  apiKey: getEnv('OPNSENSE_API_KEY'),
  apiSecret: getEnv('OPNSENSE_API_SECRET'),
  verifySSL: getEnv('OPNSENSE_VERIFY_SSL', 'false') === 'true',
  timeout: parseInt(getEnv('OPNSENSE_TIMEOUT', '30000')),
  
  // Configurazione certificati SSL
  ssl: {
    ca: null,
    cert: null,
    key: null
  }
};

console.log('OPNsense configuration loaded successfully');

// Carica certificati se presenti
const certsDir = path.join(__dirname, '../../certs');

try {
  // CA Certificate (Authority Certificate in PEM format)
  const caPath = path.join(certsDir, 'ca.pem');
  if (fs.existsSync(caPath)) {
    config.ssl.ca = fs.readFileSync(caPath, 'utf8');
    console.log('CA certificate loaded from ca.pem');
  } else {
    // Prova anche con estensione .crt
    const caCrtPath = path.join(certsDir, 'ca.crt');
    if (fs.existsSync(caCrtPath)) {
      config.ssl.ca = fs.readFileSync(caCrtPath, 'utf8');
      console.log('CA certificate loaded from ca.crt');
    }
  }

  // Client Certificate (PEM format)
  const certPath = path.join(certsDir, 'client.pem');
  if (fs.existsSync(certPath)) {
    config.ssl.cert = fs.readFileSync(certPath, 'utf8');
    console.log('Client certificate loaded from client.pem');
  } else {
    // Prova anche con estensione .crt
    const clientCrtPath = path.join(certsDir, 'client.crt');
    if (fs.existsSync(clientCrtPath)) {
      config.ssl.cert = fs.readFileSync(clientCrtPath, 'utf8');
      console.log('Client certificate loaded from client.crt');
    }
  }

  // Client Private Key (PEM format)
  const keyPath = path.join(certsDir, 'client.key');
  if (fs.existsSync(keyPath)) {
    config.ssl.key = fs.readFileSync(keyPath, 'utf8');
    console.log('Client private key loaded from client.key');
  }

  // Supporto per variabili ambiente alternative
  const caCertPath = getEnv('OPNSENSE_CA_CERT_PATH');
  if (!config.ssl.ca && caCertPath && fs.existsSync(caCertPath)) {
    config.ssl.ca = fs.readFileSync(caCertPath, 'utf8');
    console.log(`CA certificate loaded from env: ${caCertPath}`);
  }

  const clientCertPath = getEnv('OPNSENSE_CLIENT_CERT_PATH');
  if (!config.ssl.cert && clientCertPath && fs.existsSync(clientCertPath)) {
    config.ssl.cert = fs.readFileSync(clientCertPath, 'utf8');
    console.log(`Client certificate loaded from env: ${clientCertPath}`);
  }

  const clientKeyPath = getEnv('OPNSENSE_CLIENT_KEY_PATH');
  if (!config.ssl.key && clientKeyPath && fs.existsSync(clientKeyPath)) {
    config.ssl.key = fs.readFileSync(clientKeyPath, 'utf8');
    console.log(`Client key loaded from env: ${clientKeyPath}`);
  }

} catch (error) {
  console.warn('Attenzione: Errore nel caricamento dei certificati SSL:', error.message);
  console.warn('   L\'API continuerà senza certificati client, usando solo verifica SSL di base');
}

// Validazione configurazione
const validateConfig = () => {
  // Verifica formato host
  if (!config.host.startsWith('http://') && !config.host.startsWith('https://')) {
    config.host = `https://${config.host}`;
  }

  // Rimuovi trailing slash
  config.host = config.host.replace(/\/$/, '');
 
  // Log configurazione SSL
  console.log('SSL Configuration:');
  console.log(`   - SSL Verification: ${config.verifySSL ? 'ENABLED' : 'DISABLED'}`);
  console.log(`   - CA Certificate: ${config.ssl.ca ? 'LOADED' : 'NOT FOUND'}`);
  console.log(`   - Client Certificate: ${config.ssl.cert ? 'LOADED' : 'NOT FOUND'}`);
  console.log(`   - Client Private Key: ${config.ssl.key ? 'LOADED' : 'NOT FOUND'}`);

  if (config.verifySSL && !config.ssl.ca) {
    console.warn('SSL verification is enabled but no CA certificate found.');
    console.warn('   Place your CA certificate as certs/ca.pem or certs/ca.crt');
    console.warn('   Or set OPNSENSE_CA_CERT_PATH environment variable');
  }
};

validateConfig();

module.exports = config;