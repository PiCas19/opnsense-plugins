// tests/setup/testSetup.js
const fixtures = require('./fixtures');

// Verifica che i fixtures siano caricati correttamente
if (!fixtures.isReady()) {
  console.warn('Fixtures not properly loaded. Debug info:', fixtures.getDebugInfo());
}

// Espone i fixtures globalmente per uso nei test
global.fixtures = fixtures;

// Alias per retrocompatibilità (nel caso qualche test vecchio li usi)
global.FixturesHelper = fixtures;
global.mockResponses = fixtures.getMockResponse;
global.testData = fixtures.getTestData;

// Configurazione Jest globale
jest.setTimeout(10000);

// Mock console methods per ridurre il rumore durante i test
if (process.env.NODE_ENV === 'test') {
  const originalError = console.error;
  const originalWarn = console.warn;
  
  console.error = (...args) => {
    // Filtra solo alcuni tipi di errori che vogliamo nascondere
    const message = args[0]?.toString() || '';
    if (message.includes('Warning:') || message.includes('validateDOMNesting')) {
      return; // Nasconde warning React durante i test
    }
    originalError.apply(console, args);
  };
  
  console.warn = (...args) => {
    // Nasconde alcuni warning specifici
    const message = args[0]?.toString() || '';
    if (message.includes('componentWillReceiveProps') || message.includes('deprecated')) {
      return;
    }
    originalWarn.apply(console, args);
  };
}

// Setup globale per ogni test
beforeEach(() => {
  // Pulisce tutte le implementazioni mock
  jest.clearAllMocks();
  
  // Reset di Date.now per test deterministici
  if (global.mockDate) {
    global.mockDate.mockRestore();
  }
});

afterEach(() => {
  // Ripristina tutti i mock e spy
  jest.restoreAllMocks();
  
  // Pulisce tutti i timer
  if (jest.getTimerCount && jest.getTimerCount() > 0) {
    jest.clearAllTimers();
    jest.useRealTimers();
  }
  
  // Reset dello stato dei fixtures
  fixtures.reset();
});

// Setup per test di integrazione
beforeAll(() => {
  // Configura l'ambiente di test
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error'; // Riduce i log durante i test
});

afterAll(() => {
  // Cleanup finale
  if (global.gc) {
    global.gc(); // Garbage collection se disponibile
  }
});

// Utility helpers globali per i test
global.testHelpers = {
  /**
   * Aspetta che una promessa venga risolta/rigettata
   * @param {Function} fn - Funzione che ritorna una promessa
   * @param {number} timeout - Timeout in ms
   */
  async waitFor(fn, timeout = 1000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const result = await fn();
        if (result) return result;
      } catch (error) {
        // Continua a provare
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error(`waitFor timeout after ${timeout}ms`);
  },

  /**
   * Simula un delay asincrono
   * @param {number} ms - Millisecondi di delay
   */
  async delay(ms = 0) {
    return new Promise(resolve => setTimeout(resolve, ms));
  },

  /**
   * Crea un mock di Date.now deterministico
   * @param {number|Date} timestamp - Timestamp o Date object
   */
  mockDate(timestamp = Date.now()) {
    const mockTime = timestamp instanceof Date ? timestamp.getTime() : timestamp;
    global.mockDate = jest.spyOn(Date, 'now').mockReturnValue(mockTime);
    return global.mockDate;
  },

  /**
   * Genera dati casuali per test
   */
  random: {
    string(length = 10) {
      return Math.random().toString(36).substring(2, 2 + length);
    },
    
    number(min = 0, max = 100) {
      return Math.floor(Math.random() * (max - min + 1)) + min;
    },
    
    email() {
      return `test-${this.string(8)}@example.com`;
    },
    
    ip() {
      return `192.168.${this.number(1, 254)}.${this.number(1, 254)}`;
    },
    
    port() {
      return this.number(1024, 65535);
    }
  },

  /**
   * Assertions personalizzate
   */
  expect: {
    toBeValidUUID(received) {
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      return {
        message: () => `expected ${received} to be a valid UUID`,
        pass: uuidRegex.test(received)
      };
    },
    
    toBeValidIP(received) {
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      return {
        message: () => `expected ${received} to be a valid IP address`,
        pass: ipRegex.test(received)
      };
    },
    
    toHaveValidTimestamp(received) {
      const timestamp = new Date(received);
      return {
        message: () => `expected ${received} to be a valid timestamp`,
        pass: !isNaN(timestamp.getTime())
      };
    }
  }
};

// Estende Jest con le assertions personalizzate
if (expect.extend) {
  expect.extend(global.testHelpers.expect);
}

// Log di inizializzazione
console.log('Test environment initialized');
if (fixtures.isReady()) {
  console.log('Fixtures loaded successfully');
} else {
  console.log('Fixtures failed to load');
}

module.exports = fixtures;