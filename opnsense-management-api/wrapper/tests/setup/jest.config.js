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
    '/dist/',
    '/build/'
  ],
  
  // Module paths
  moduleDirectories: ['node_modules', 'src'],
  
  // File extensions to consider
  moduleFileExtensions: ['js', 'json', 'jsx', 'ts', 'tsx'],
  
  // Transform files
  transform: {
    '^.+\\.(js|jsx)$': 'babel-jest'
  },
  
  // Module name mapping (per path aliases)
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@fixtures/(.*)$': '<rootDir>/tests/fixtures/$1',
    '^@setup/(.*)$': '<rootDir>/tests/setup/$1'
  },
  
  // Coverage settings
  collectCoverage: false, // Abilitato solo quando necessario
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/app.js',
    '!src/server.js',
    '!src/config/**',
    '!src/database/migrations/*.js',
    '!src/database/seeders/*.js',
    '!src/scripts/*.js',
    '!**/node_modules/**',
    '!**/coverage/**',
    '!**/tests/**'
  ],
  
  // Coverage output
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'text-summary', 
    'lcov',
    'html',
    'json-summary'
  ],
  
  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    },
    // Thresholds specifici per file critici
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
    },
    './src/middleware/errorHandler.js': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85
    }
  },
  
  // Test timeout (milliseconds)
  testTimeout: 15000, // Aumentato per test più complessi
  
  // Verbose output
  verbose: true,
  
  // Error handling
  errorOnDeprecated: true,
  
  // Clear mocks between tests
  clearMocks: true,
  restoreMocks: true,
  resetMocks: false, // Evita problemi con alcuni mock
  
  // Global variables available in tests
  globals: {
    NODE_ENV: 'test',
    __DEV__: false,
    __TEST__: true
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
        includeSuiteFailure: true,
        includeConsoleLog: true,
        theme: 'defaultTheme',
        logo: ''
      }
    ],
    [
      'jest-junit', 
      {
        outputDirectory: 'coverage',
        outputName: 'junit.xml',
        classNameTemplate: '{classname}',
        titleTemplate: '{title}',
        ancestorSeparator: ' › ',
        usePathForSuiteName: true
      }
    ]
  ],
  
  // Watch mode settings
  watchPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/logs/',
    '/temp/',
    '/dist/',
    '/build/'
  ],
  
  // Watch plugins
  watchPlugins: [
    'jest-watch-typeahead/filename',
    'jest-watch-typeahead/testname'
  ],
  
  // Force exit after tests complete
  forceExit: true,
  
  // Detect open handles
  detectOpenHandles: true,
  detectLeaks: false, // Può causare falsi positivi
  
  // Maximum worker processes
  maxWorkers: process.env.CI ? 2 : '50%',
  
  // Cache directory
  cacheDirectory: '<rootDir>/node_modules/.cache/jest',
  
  // Preset configurations for different test types
  projects: [
    {
      displayName: {
        name: 'unit',
        color: 'blue'
      },
      testMatch: ['<rootDir>/tests/unit/**/*.test.js'],
      testEnvironment: 'node',
      setupFilesAfterEnv: ['<rootDir>/tests/setup/testSetup.js']
    },
    {
      displayName: {
        name: 'integration',
        color: 'yellow'
      },
      testMatch: ['<rootDir>/tests/integration/**/*.test.js'],
      testEnvironment: 'node',
      testTimeout: 30000, // Timeout più lungo per integration tests
      setupFilesAfterEnv: ['<rootDir>/tests/setup/testSetup.js'],
      maxWorkers: 1 // I test di integrazione spesso devono girare in sequenza
    }
  ],
  
  // Custom test sequencer (esegue unit test prima)
  testSequencer: '<rootDir>/tests/setup/testSequencer.js',
  
  // Configurazioni ambiente specifiche
  testEnvironmentOptions: {
    node: {
      // Opzioni specifiche per Node.js
    }
  },
  
  // Notifiche (solo in modalità watch)
  notify: false,
  notifyMode: 'failure-change',
  
  // Configurazioni per snapshot testing
  snapshotSerializers: [],
  
  // Configurazioni per mock
  automock: false,
  unmockedModulePathPatterns: [],
  
  // Configurazioni per la risoluzione dei moduli
  resolver: undefined,
  rootDir: undefined,
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  
  // Configurazioni per la trasformazione
  transformIgnorePatterns: [
    '/node_modules/(?!(.*\\.mjs$))'
  ],
  
  // Configurazioni avanzate
  extensionsToTreatAsEsm: ['.mjs'],
  
  // Configurazioni per test con database
  globalSetup: undefined,
  globalTeardown: undefined,
  
  // Configurazioni per performance
  slowTestThreshold: 5, // Considera lenti i test che durano più di 5 secondi
  
  // Configurazioni per il debugging
  silent: false, // Permette console.log nei test
  
  // Configurazioni per CI/CD
  ci: process.env.CI === 'true',
  
  // Configurazioni per i test runner
  maxConcurrency: 5,
  
  // Configurazioni per errori
  collectCoverageOnlyFrom: undefined,
  coverageProvider: 'v8', // Più veloce di babel
  
  // Hook per setup/teardown personalizzati
  setupFiles: [],
  
  // Configurazioni per timeout specifici
  testNamePattern: undefined,
  testPathPattern: undefined,
  
  // Configurazioni per il mock del filesystem
  fakeTimers: {
    enableGlobally: false
  }
};