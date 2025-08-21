// utils/env.js - Lazy environment loader
const fs = require('fs');
const path = require('path');

let envLoaded = false;

/**
 * Carica le variabili d'ambiente in modo lazy
 */
const loadEnv = () => {
  if (envLoaded) return;

  try {
    const envPath = path.join(process.cwd(), '.env');
    
    if (fs.existsSync(envPath)) {
      const envContent = fs.readFileSync(envPath, 'utf8');
      
      envContent.split('\n').forEach(line => {
        line = line.trim();
        
        // Ignora commenti e righe vuote
        if (!line || line.startsWith('#')) return;
        
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length > 0) {
          const value = valueParts.join('=').trim();
          // Rimuovi quotes se presenti
          const cleanValue = value.replace(/^["']|["']$/g, '');
          process.env[key.trim()] = cleanValue;
        }
      });
      
      console.log('Environment variables loaded successfully');
    } else {
      console.warn('.env file not found, using system environment variables');
    }
    
    envLoaded = true;
  } catch (error) {
    console.error('Error loading .env file:', error.message);
  }
};

/**
 * Ottieni variabile d'ambiente con lazy loading
 */
const getEnv = (key, defaultValue = null) => {
  loadEnv();
  return process.env[key] || defaultValue;
};

/**
 * Verifica che le variabili richieste siano presenti
 */
const requireEnv = (keys) => {
  loadEnv();
  
  const missing = keys.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error('Missing required environment variables:', missing.join(', '));
    console.error('Make sure your .env file contains:');
    missing.forEach(key => console.error(`${key}=your_value_here`));
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  return true;
};

module.exports = {
  loadEnv,
  getEnv,
  requireEnv
};