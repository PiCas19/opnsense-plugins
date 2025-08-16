// tests/setup/jest.config.js
module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Setup files
  setupFilesAfterEnv: ['<rootDir>/tests/setup/testSetup.js'],
  
  // Test patterns
  testMatch: [
    '**/tests/**/*.test.js',
    '**/tests/**/*.spec.js'
  ],
  
  // Ignore patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/logs/',
    '/temp/',
    '/dist/'
  ],
  
  // Module paths
  moduleDirectories: ['node_modules', 'src'],
  
  // File extensions to consider
  moduleFileExtensions: ['js', 'json'],
  
  // Transform files
  transform: {},
  
  // Coverage settings
  collectCoverage: true,
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/app.js',
    '!src/database/migrations/*.js',
    '!src/database/seeders/*.js',
    '!src/scripts/*.js',
    '!**/node_modules/**',
    '!**/coverage/**'
  ],
  
  // Coverage output
  coverageDirectory: 'coverage',
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
    },
    // Specific thresholds for critical files
    './src/middleware/auth.js': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85
    },
    './src/services/OpnsenseService.js': {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  
  // Test timeout (milliseconds)
  testTimeout: 10000,
  
  // Verbose output
  verbose: true,
  
  // Error handling
  errorOnDeprecated: true,
  
  // Clear mocks between tests
  clearMocks: true,
  restoreMocks: true,
  
  // Global variables available in tests
  globals: {
    NODE_ENV: 'test'
  },
  
  // Module name mapping (for path aliases)
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1'
  },
  
  // Test reporter
  reporters: [
    'default',
    [
      'jest-html-reporter',
      {
        pageTitle: 'OPNsense Management API Test Report',
        outputPath: 'coverage/test-report.html',
        includeFailureMsg: true,
        includeSuiteFailure: true
      }
    ]
  ],
  
  // Watch mode settings
  watchPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/logs/',
    '/temp/'
  ],
  
  // Force exit after tests complete
  forceExit: true,
  
  // Detect open handles
  detectOpenHandles: true,
  
  // Maximum worker processes
  maxWorkers: '50%',
  
  // Cache directory
  cacheDirectory: '<rootDir>/node_modules/.cache/jest',
  
  // Preset configurations for different test types
  projects: [
    {
      displayName: 'unit',
      testMatch: ['<rootDir>/tests/unit/**/*.test.js'],
      testEnvironment: 'node'
    },
    {
      displayName: 'integration', 
      testMatch: ['<rootDir>/tests/integration/**/*.test.js'],
      testEnvironment: 'node',
      testTimeout: 30000 // Longer timeout for integration tests
    }
  ],
  
  // Setup for different test environments
  testEnvironmentOptions: {
    node: {
      // Node.js specific options
    }
  },
  
  // Custom test sequencer (run unit tests first)
  testSequencer: '<rootDir>/tests/setup/testSequencer.js'
};