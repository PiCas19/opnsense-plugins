#!/usr/bin/env node

/**
 * Healthcheck script per Docker
 * Esce con codice 0 se l'applicazione è healthy, 1 altrimenti
 */

const http = require('http');

const options = {
  hostname: 'localhost',
  port: process.env.PORT || 3000,
  path: '/api/health',
  method: 'GET',
  timeout: 5000
};

const request = http.request(options, (res) => {
  let data = '';
  
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    try {
      const response = JSON.parse(data);
      
      if (res.statusCode === 200 && response.success) {
        console.log('Health check passed');
        process.exit(0);
      } else {
        console.error('Health check failed:', response.message || 'Unknown error');
        process.exit(1);
      }
    } catch (error) {
      console.error('Health check failed: Invalid JSON response');
      process.exit(1);
    }
  });
});

request.on('error', (error) => {
  console.error('Health check failed:', error.message);
  process.exit(1);
});

request.on('timeout', () => {
  console.error('Health check failed: Timeout');
  request.destroy();
  process.exit(1);
});

request.setTimeout(5000);
request.end();