#!/usr/bin/env node

/**
 * Healthcheck script per Docker
 * Esce con codice 0 se l'applicazione è healthy, 1 altrimenti
 */

const http = require('http');
const https = require('https');
const url = require('url');

// Configurazione
const config = {
  host: process.env.HEALTHCHECK_HOST || 'localhost',
  port: process.env.PORT || 3000,
  path: '/api/health',
  timeout: parseInt(process.env.HEALTHCHECK_TIMEOUT) || 5000,
  useHttps: process.env.HEALTHCHECK_HTTPS === 'true'
};

/**
 * Effettua health check
 */
function performHealthCheck() {
  const protocol = config.useHttps ? https : http;
  const requestUrl = `${config.useHttps ? 'https' : 'http'}://${config.host}:${config.port}${config.path}`;
  
  console.log(`Performing health check: ${requestUrl}`);
  
  const options = {
    hostname: config.host,
    port: config.port,
    path: config.path,
    method: 'GET',
    timeout: config.timeout,
    headers: {
      'User-Agent': 'HealthCheck/1.0'
    }
  };

  // Per HTTPS, ignora certificati self-signed in development
  if (config.useHttps && process.env.NODE_ENV !== 'production') {
    options.rejectUnauthorized = false;
  }

  const request = protocol.request(options, (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      try {
        const response = JSON.parse(data);
        
        if (res.statusCode === 200 && response.success) {
          console.log('✅ Health check passed');
          console.log(`   Status: ${res.statusCode}`);
          console.log(`   Uptime: ${response.uptime ? Math.floor(response.uptime) + 's' : 'N/A'}`);
          console.log(`   Version: ${response.version || 'N/A'}`);
          process.exit(0);
        } else {
          console.error('❌ Health check failed');
          console.error(`   Status: ${res.statusCode}`);
          console.error(`   Message: ${response.message || 'Unknown error'}`);
          process.exit(1);
        }
      } catch (error) {
        console.error('❌ Health check failed: Invalid JSON response');
        console.error(`   Status: ${res.statusCode}`);
        console.error(`   Data: ${data}`);
        process.exit(1);
      }
    });
  });

  request.on('error', (error) => {
    console.error('❌ Health check failed:', error.message);
    
    // Dettagli specifici per errori comuni
    if (error.code === 'ECONNREFUSED') {
      console.error('   Server is not running or not accepting connections');
    } else if (error.code === 'ETIMEDOUT') {
      console.error('   Request timed out');
    } else if (error.code === 'ENOTFOUND') {
      console.error('   Host not found');
    }
    
    process.exit(1);
  });

  request.on('timeout', () => {
    console.error('❌ Health check failed: Request timeout');
    request.destroy();
    process.exit(1);
  });

  request.setTimeout(config.timeout);
  request.end();
}

/**
 * Advanced health check con multiple endpoint
 */
function performAdvancedHealthCheck() {
  const endpoints = [
    '/api/health',
    '/api/health/database',
    '/api/health/opnsense'
  ];
  
  let completed = 0;
  let failed = 0;
  const results = [];

  console.log('Performing advanced health check...');

  endpoints.forEach((endpoint, index) => {
    const options = {
      hostname: config.host,
      port: config.port,
      path: endpoint,
      method: 'GET',
      timeout: config.timeout,
      headers: {
        'User-Agent': 'HealthCheck/1.0'
      }
    };

    const protocol = config.useHttps ? https : http;
    const request = protocol.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        completed++;
        
        try {
          const response = JSON.parse(data);
          const success = res.statusCode === 200 && response.success;
          
          results.push({
            endpoint,
            status: res.statusCode,
            success,
            message: response.message || 'No message'
          });
          
          if (!success) failed++;
          
        } catch (error) {
          failed++;
          results.push({
            endpoint,
            status: res.statusCode,
            success: false,
            message: 'Invalid JSON response'
          });
        }
        
        // Controlla se tutti i check sono completati
        if (completed === endpoints.length) {
          finishAdvancedCheck();
        }
      });
    });

    request.on('error', (error) => {
      completed++;
      failed++;
      results.push({
        endpoint,
        status: 'ERROR',
        success: false,
        message: error.message
      });
      
      if (completed === endpoints.length) {
        finishAdvancedCheck();
      }
    });

    request.on('timeout', () => {
      completed++;
      failed++;
      results.push({
        endpoint,
        status: 'TIMEOUT',
        success: false,
        message: 'Request timeout'
      });
      
      request.destroy();
      
      if (completed === endpoints.length) {
        finishAdvancedCheck();
      }
    });

    request.setTimeout(config.timeout);
    request.end();
  });

  function finishAdvancedCheck() {
    console.log('\n📊 Advanced Health Check Results:');
    console.log('═══════════════════════════════════');
    
    results.forEach(result => {
      const icon = result.success ? '✅' : '❌';
      console.log(`${icon} ${result.endpoint}`);
      console.log(`   Status: ${result.status}`);
      console.log(`   Message: ${result.message}`);
      console.log('');
    });
    
    console.log(`Summary: ${endpoints.length - failed}/${endpoints.length} checks passed`);
    
    // Considera healthy se almeno l'endpoint base funziona
    const baseEndpointResult = results.find(r => r.endpoint === '/api/health');
    if (baseEndpointResult && baseEndpointResult.success) {
      console.log('🎉 Overall status: HEALTHY');
      process.exit(0);
    } else {
      console.log('💥 Overall status: UNHEALTHY');
      process.exit(1);
    }
  }
}

/**
 * Wait for service to be ready
 */
function waitForService(maxWaitTime = 60000) {
  const interval = 2000; // 2 secondi
  const maxAttempts = Math.floor(maxWaitTime / interval);
  let attempts = 0;

  console.log(`Waiting for service to be ready (max ${maxWaitTime / 1000}s)...`);

  function attempt() {
    attempts++;
    console.log(`Attempt ${attempts}/${maxAttempts}`);

    const options = {
      hostname: config.host,
      port: config.port,
      path: config.path,
      method: 'GET',
      timeout: 3000
    };

    const protocol = config.useHttps ? https : http;
    const request = protocol.request(options, (res) => {
      if (res.statusCode === 200) {
        console.log('✅ Service is ready!');
        process.exit(0);
      } else {
        if (attempts >= maxAttempts) {
          console.error('❌ Service failed to become ready');
          process.exit(1);
        } else {
          setTimeout(attempt, interval);
        }
      }
    });

    request.on('error', () => {
      if (attempts >= maxAttempts) {
        console.error('❌ Service failed to become ready');
        process.exit(1);
      } else {
        setTimeout(attempt, interval);
      }
    });

    request.on('timeout', () => {
      request.destroy();
      if (attempts >= maxAttempts) {
        console.error('❌ Service failed to become ready');
        process.exit(1);
      } else {
        setTimeout(attempt, interval);
      }
    });

    request.setTimeout(3000);
    request.end();
  }

  attempt();
}

// CLI interface
function main() {
  const command = process.argv[2];
  
  switch (command) {
    case 'advanced':
      performAdvancedHealthCheck();
      break;
    case 'wait':
      const waitTime = parseInt(process.argv[3]) || 60000;
      waitForService(waitTime);
      break;
    case 'help':
    case '--help':
    case '-h':
      console.log('Health Check Utility');
      console.log('');
      console.log('Usage:');
      console.log('  node healthcheck.js [command]');
      console.log('');
      console.log('Commands:');
      console.log('  (none)     Perform basic health check');
      console.log('  advanced   Perform advanced health check');
      console.log('  wait [ms]  Wait for service to be ready');
      console.log('  help       Show this help message');
      console.log('');
      console.log('Environment Variables:');
      console.log('  HEALTHCHECK_HOST     Target host (default: localhost)');
      console.log('  PORT                 Target port (default: 3000)');
      console.log('  HEALTHCHECK_TIMEOUT  Request timeout in ms (default: 5000)');
      console.log('  HEALTHCHECK_HTTPS    Use HTTPS (default: false)');
      break;
    default:
      performHealthCheck();
      break;
  }
}

// Esegui se script chiamato direttamente
if (require.main === module) {
  main();
}

module.exports = {
  performHealthCheck,
  performAdvancedHealthCheck,
  waitForService
};