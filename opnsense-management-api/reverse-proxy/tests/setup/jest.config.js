/**
 * Jest Configuration for OPNsense Reverse Proxy Tests
 * Comprehensive testing setup for end-to-end, integration, and unit tests
 */

module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Root directory for tests
  rootDir: '../',
  
  // Setup files
  setupFilesAfterEnv: [
    '<rootDir>/setup/testSetup.js'
  ],
  
  // Test file patterns
  testMatch: [
    '<rootDir>/e2e/**/*.test.js',
    '<rootDir>/e2e/**/*.spec.js'
  ],
  
  // Ignore patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/fixtures/',
    '/.git/'
  ],
  
  // Coverage configuration
  collectCoverage: false, // Enable with --coverage flag
  collectCoverageFrom: [
    'e2e/**/*.js',
    '!e2e/**/node_modules/**',
    '!e2e/**/coverage/**',
    '!e2e/**/fixtures/**',
    '!e2e/**/setup/**'
  ],
  
  // Coverage output
  coverageDirectory: '<rootDir>/coverage',
  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json'
  ],
  
  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  },
  
  // Test timeouts
  testTimeout: 30000, // 30 seconds default
  
  // Concurrent test execution
  maxWorkers: 2, // Limit parallel tests to avoid overwhelming services
  
  // Test execution settings
  verbose: true,
  detectOpenHandles: true,
  forceExit: true,
  
  // Module resolution
  moduleDirectories: [
    'node_modules',
    '<rootDir>'
  ],
  
  // Module file extensions
  moduleFileExtensions: [
    'js',
    'json',
    'jsx',
    'ts',
    'tsx',
    'node'
  ],
  
  // Transform configuration (if using TypeScript or modern JS)
  transform: {
    '^.+\\.(js|jsx)$': 'babel-jest'
  },
  
  // Global variables available in all tests
  globals: {
    'TEST_ENVIRONMENT': 'e2e',
    'BASE_URL': 'https://localhost',
    'GRAFANA_URL': 'https://localhost/grafana',
    'API_URL': 'https://localhost/api'
  },
  
  // Test result processors
  reporters: [
    'default',
    [
      'jest-html-reporters',
      {
        publicPath: './coverage/html-report',
        filename: 'test-report.html',
        expand: true,
        hideIcon: false,
        pageTitle: 'OPNsense Reverse Proxy Test Report'
      }
    ]
  ],
  
  // Custom test environments for different test types
  projects: [
    {
      displayName: 'nginx',
      testMatch: ['<rootDir>/e2e/nginx/**/*.test.js'],
      setupFilesAfterEnv: ['<rootDir>/setup/testSetup.js'],
      testTimeout: 15000
    },
    {
      displayName: 'grafana',
      testMatch: ['<rootDir>/e2e/grafana/**/*.test.js'],
      setupFilesAfterEnv: ['<rootDir>/setup/testSetup.js'],
      testTimeout: 20000
    },
    {
      displayName: 'full-stack',
      testMatch: ['<rootDir>/e2e/full-stack/**/*.test.js'],
      setupFilesAfterEnv: ['<rootDir>/setup/testSetup.js'],
      testTimeout: 45000
    },
    {
      displayName: 'performance',
      testMatch: ['<rootDir>/e2e/**/performance.test.js'],
      setupFilesAfterEnv: ['<rootDir>/setup/testSetup.js'],
      testTimeout: 60000
    }
  ],
  
  // Error handling
  errorOnDeprecated: true,
  
  // Clear mocks between tests
  clearMocks: true,
  restoreMocks: true,
  
  // Watch mode settings
  watchPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/.git/'
  ],
  
  // Notification settings for watch mode
  notify: false,
  notifyMode: 'failure-change',
  
  // Snapshot settings
  updateSnapshot: false,
  
  // Custom matchers and utilities
  setupFiles: [],
  
  // Test retry configuration
  retry: {
    // Retry failed tests up to 2 times
    retries: 2,
    // Only retry tests that failed due to network/timing issues
    retryImmediately: false
  },
  
  // Logging configuration
  silent: false,
  
  // Custom test name pattern
  testNamePattern: undefined,
  
  // Bail settings - stop after first failure in CI
  bail: process.env.CI ? 1 : 0,
  
  // Cache configuration
  cache: true,
  cacheDirectory: '<rootDir>/node_modules/.cache/jest',
  
  // Custom environment variables for tests
  testEnvironmentOptions: {
    url: 'https://localhost'
  },
  
  // Dependency extraction (for better caching)
  dependencyExtractor: undefined,
  
  // Module mapper for path aliases
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/$1',
    '^@fixtures/(.*)$': '<rootDir>/fixtures/$1',
    '^@utils/(.*)$': '<rootDir>/utils/$1'
  },
  
  // Pre-processor for test files
  preprocessorIgnorePatterns: [
    '/node_modules/'
  ],
  
  // Test result processor for custom formatting
  testResultsProcessor: undefined,
  
  // Watch plugins for enhanced watch mode
  watchPlugins: [
    'jest-watch-typeahead/filename',
    'jest-watch-typeahead/testname'
  ],
  
  // Custom test sequencer (run tests in specific order)
  testSequencer: undefined,
  
  // Snapshot resolver
  snapshotResolver: undefined,
  
  // Transform ignore patterns
  transformIgnorePatterns: [
    '/node_modules/(?!(@babel|babel-runtime)/)'
  ],
  
  // Unmocked module patterns
  unmockedModulePathPatterns: undefined,
  
  // Test match patterns for different environments
  ...(process.env.TEST_TYPE === 'unit' && {
    testMatch: ['<rootDir>/unit/**/*.test.js']
  }),
  
  ...(process.env.TEST_TYPE === 'integration' && {
    testMatch: ['<rootDir>/integration/**/*.test.js']
  }),
  
  ...(process.env.TEST_TYPE === 'e2e' && {
    testMatch: ['<rootDir>/e2e/**/*.test.js']
  })
};