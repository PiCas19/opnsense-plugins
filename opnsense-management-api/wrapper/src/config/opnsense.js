const fs = require('fs');
const path = require('path');

const config = {
  host: process.env.OPNSENSE_HOST,
  apiKey: process.env.OPNSENSE_API_KEY,
  apiSecret: process.env.OPNSENSE_API_SECRET,
  verifySSL: process.env.OPNSENSE_VERIFY_SSL === 'true',
  timeout: parseInt(process.env.OPNSENSE_TIMEOUT) || 30000,
  
  // Configurazione certificati SSL
  ssl: {
    ca: null,
    cert: null,
    key: null
  }
};

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
  if (!config.ssl.ca && process.env.OPNSENSE_CA_CERT_PATH) {
    if (fs.existsSync(process.env.OPNSENSE_CA_CERT_PATH)) {
      config.ssl.ca = fs.readFileSync(process.env.OPNSENSE_CA_CERT_PATH, 'utf8');
      console.log(`CA certificate loaded from env: ${process.env.OPNSENSE_CA_CERT_PATH}`);
    }
  }

  if (!config.ssl.cert && process.env.OPNSENSE_CLIENT_CERT_PATH) {
    if (fs.existsSync(process.env.OPNSENSE_CLIENT_CERT_PATH)) {
      config.ssl.cert = fs.readFileSync(process.env.OPNSENSE_CLIENT_CERT_PATH, 'utf8');
      console.log(`Client certificate loaded from env: ${process.env.OPNSENSE_CLIENT_CERT_PATH}`);
    }
  }

  if (!config.ssl.key && process.env.OPNSENSE_CLIENT_KEY_PATH) {
    if (fs.existsSync(process.env.OPNSENSE_CLIENT_KEY_PATH)) {
      config.ssl.key = fs.readFileSync(process.env.OPNSENSE_CLIENT_KEY_PATH, 'utf8');
      console.log(`Client key loaded from env: ${process.env.OPNSENSE_CLIENT_KEY_PATH}`);
    }
  }

} catch (error) {
  console.warn('Attenzione: Errore nel caricamento dei certificati SSL:', error.message);
  console.warn('   L\'API continuerà senza certificati client, usando solo verifica SSL di base');
}

// Validazione configurazione
const validateConfig = () => {
  const required = ['host', 'apiKey', 'apiSecret'];
  const missing = required.filter(key => !config[key]);
  
  if (missing.length > 0) {
    throw new Error(`Configurazione OPNsense mancante: ${missing.join(', ')}`);
  }

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