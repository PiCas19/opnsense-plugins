/**
 * Test Setup Configuration for OPNsense Reverse Proxy Tests
 * Configures Jest environment and global test utilities
 */

const dotenv = require('dotenv');
const path = require('path');
const axios = require('axios');
const https = require('https');

// Load environment variables from project root
dotenv.config({ path: path.join(__dirname, '../../.env') });

// Global test configuration
global.testConfig = {
  // Base URLs for testing
  baseURL: process.env.TEST_BASE_URL || 'https://localhost',
  grafanaURL: process.env.TEST_GRAFANA_URL || 'https://localhost/grafana',
  apiURL: process.env.TEST_API_URL || 'https://localhost/api',
  
  // OPNsense wrapper configuration
  wrapperURL: process.env.OPNSENSE_API_URL || 'http://192.168.216.50:3000',
  wrapperHost: process.env.OPNSENSE_API_HOST || '192.168.216.50',
  wrapperPort: process.env.OPNSENSE_API_PORT || '3000',
  
  // Test credentials
  basicAuth: {
    username: process.env.BASIC_AUTH_USER || 'admin',
    password: process.env.BASIC_AUTH_PASSWORD || 'admin123'
  },
  
  grafanaAuth: {
    username: process.env.GF_ADMIN_USER || 'admin',
    password: process.env.GF_ADMIN_PASSWORD || 'admin123'
  },
  
  // JWT token for API testing
  jwtToken: process.env.JWT_TOKEN || '',
  
  // Test timeouts (milliseconds)
  timeouts: {
    short: 5000,
    medium: 15000,
    long: 30000,
    veryLong: 60000
  },
  
  // Test data
  testData: {
    validFirewallRule: {
      interface: 'wan',
      direction: 'in',
      action: 'pass',
      protocol: 'tcp',
      source: 'any',
      destination: 'any',
      port: '80',
      description: 'Test HTTP rule'
    },
    
    invalidFirewallRule: {
      interface: 'invalid',
      direction: 'invalid',
      action: 'invalid'
    }
  },
  
  // Performance thresholds
  performance: {
    maxResponseTime: 5000,
    maxLoadTime: 10000,
    minThroughput: 100 // requests per second
  }
};

// Create axios instance with SSL verification disabled for self-signed certificates
global.httpClient = axios.create({
  httpsAgent: new https.Agent({
    rejectUnauthorized: false
  }),
  timeout: global.testConfig.timeouts.medium,
  validateStatus: () => true // Don't throw on HTTP errors
});

// Helper function to wait for service to be ready
global.waitForService = async (url, maxAttempts = 30, delay = 2000) => {
  console.log(`Waiting for service at ${url}...`);
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await global.httpClient.get(url);
      if (response.status === 200) {
        console.log(`Service at ${url} is ready (attempt ${attempt})`);
        return true;
      }
    } catch (error) {
      // Service not ready yet
    }
    
    if (attempt < maxAttempts) {
      console.log(`Service not ready, retrying in ${delay/1000}s... (attempt ${attempt}/${maxAttempts})`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  throw new Error(`Service at ${url} did not become ready after ${maxAttempts} attempts`);
};

// Helper function to get basic auth header
global.getBasicAuthHeader = () => {
  const { username, password } = global.testConfig.basicAuth;
  const credentials = Buffer.from(`${username}:${password}`).toString('base64');
  return `Basic ${credentials}`;
};

// Helper function to get JWT auth header
global.getJWTAuthHeader = () => {
  return `Bearer ${global.testConfig.jwtToken}`;
};

// Helper function to make authenticated request
global.authenticatedRequest = async (method, url, data = null, useJWT = false) => {
  const headers = {
    'Content-Type': 'application/json'
  };
  
  if (useJWT && global.testConfig.jwtToken) {
    headers.Authorization = global.getJWTAuthHeader();
  } else {
    headers.Authorization = global.getBasicAuthHeader();
  }
  
  const config = {
    method,
    url,
    headers,
    data
  };
  
  return await global.httpClient(config);
};

// Helper function to wait for containers to be healthy
global.waitForContainers = async () => {
  console.log('Waiting for Docker containers to be healthy...');
  
  const services = [
    `${global.testConfig.baseURL}/health`,
    `${global.testConfig.grafanaURL}/api/health`
  ];
  
  for (const service of services) {
    await global.waitForService(service);
  }
  
  console.log('All services are ready!');
};

// Setup function to run before all tests
global.setupTests = async () => {
  console.log('Setting up test environment...');
  console.log('Test configuration:', {
    baseURL: global.testConfig.baseURL,
    grafanaURL: global.testConfig.grafanaURL,
    wrapperURL: global.testConfig.wrapperURL,
    basicAuthUser: global.testConfig.basicAuth.username,
    grafanaUser: global.testConfig.grafanaAuth.username
  });
  
  // Wait for services to be ready
  await global.waitForContainers();
  
  console.log('Test environment setup complete!');
};

// Cleanup function to run after all tests
global.cleanupTests = async () => {
  console.log('Cleaning up test environment...');
  
  // Clean up any test data created during tests
  try {
    // Example: Delete test firewall rules
    // await deleteTestFirewallRules();
  } catch (error) {
    console.warn('Cleanup warning:', error.message);
  }
  
  console.log('Test environment cleanup complete!');
};

// Global test utilities
global.testUtils = {
  // Generate random test data
  generateRandomString: (length = 8) => {
    return Math.random().toString(36).substring(2, length + 2);
  },
  
  // Generate test firewall rule
  generateTestRule: (overrides = {}) => {
    return {
      ...global.testConfig.testData.validFirewallRule,
      description: `Test rule ${global.testUtils.generateRandomString()}`,
      ...overrides
    };
  },
  
  // Sleep utility
  sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // Retry utility
  retry: async (fn, maxAttempts = 3, delay = 1000) => {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        if (attempt === maxAttempts) throw error;
        await global.testUtils.sleep(delay);
      }
    }
  }
};

// Jest setup hooks
beforeAll(async () => {
  await global.setupTests();
}, global.testConfig.timeouts.veryLong);

afterAll(async () => {
  await global.cleanupTests();
}, global.testConfig.timeouts.medium);

// Set longer timeout for all tests
jest.setTimeout(global.testConfig.timeouts.long);

console.log('Test setup configuration loaded successfully');

module.exports = {
  testConfig: global.testConfig,
  httpClient: global.httpClient,
  waitForService: global.waitForService,
  setupTests: global.setupTests,
  cleanupTests: global.cleanupTests,
  testUtils: global.testUtils
};