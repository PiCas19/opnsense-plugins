// tests/setup/testSequencer.js
const Sequencer = require('@jest/test-sequencer').default;
const path = require('path');

/**
 * Sequencer personalizzato che ordina i test per:
 * 1. Test critici prima (auth, errorHandler, etc.)
 * 2. Unit test prima degli integration test
 * 3. Test alfabeticamente all'interno di ogni categoria
 */
class CustomTestSequencer extends Sequencer {
  sort(tests) {
    const unitTests = [];
    const integrationTests = [];
    const otherTests = [];

    // Categorizza i test per tipo
    for (const test of tests) {
      const testPath = test.path;
      
      if (this.isUnitTest(testPath)) {
        unitTests.push(test);
      } else if (this.isIntegrationTest(testPath)) {
        integrationTests.push(test);
      } else {
        otherTests.push(test);
      }
    }

    // Ordina alfabeticamente ogni categoria
    const sortAlphabetically = (a, b) => a.path.localeCompare(b.path);
    
    unitTests.sort(sortAlphabetically);
    integrationTests.sort(sortAlphabetically);
    otherTests.sort(sortAlphabetically);

    // Identifica e prioritizza i test critici
    const { priorityTests, regularTests } = this.categorizeCriticalTests(unitTests);

    // Ordina i test di integrazione per dipendenze
    const orderedIntegrationTests = this.sortIntegrationTestsByDependency(integrationTests);

    return [
      ...priorityTests,      // Test critici per primi
      ...regularTests,       // Altri unit test
      ...otherTests,         // Test vari
      ...orderedIntegrationTests  // Test di integrazione per ultimi
    ];
  }

  /**
   * Determina se un test è un unit test
   */
  isUnitTest(testPath) {
    return testPath.includes(path.sep + 'unit' + path.sep) ||
           testPath.includes('/unit/');
  }

  /**
   * Determina se un test è un integration test
   */
  isIntegrationTest(testPath) {
    return testPath.includes(path.sep + 'integration' + path.sep) ||
           testPath.includes('/integration/');
  }

  /**
   * Categorizza i test critici che devono essere eseguiti per primi
   */
  categorizeCriticalTests(unitTests) {
    // File critici che devono essere testati per primi
    const criticalFiles = new Set([
      'auth.test.js',
      'errorHandler.test.js', 
      'rateLimit.test.js',
      'validation.test.js',
      'logger.test.js',
      'helpers.test.js'
    ]);

    // Ordine di priorità per i test critici
    const priorityOrder = [
      'logger.test.js',      // Logging per primo
      'helpers.test.js',     // Utility helpers
      'validation.test.js',  // Validazione
      'errorHandler.test.js',// Gestione errori
      'auth.test.js',       // Autenticazione
      'rateLimit.test.js'   // Rate limiting
    ];

    const priorityTests = [];
    const regularTests = [];

    // Separa i test critici da quelli regolari
    for (const test of unitTests) {
      const fileName = path.basename(test.path);
      
      if (criticalFiles.has(fileName)) {
        priorityTests.push(test);
      } else {
        regularTests.push(test);
      }
    }

    // Ordina i test critici secondo la priorità definita
    priorityTests.sort((a, b) => {
      const fileNameA = path.basename(a.path);
      const fileNameB = path.basename(b.path);
      
      const priorityA = priorityOrder.indexOf(fileNameA);
      const priorityB = priorityOrder.indexOf(fileNameB);
      
      // Se entrambi hanno priorità, usa l'ordine di priorità
      if (priorityA !== -1 && priorityB !== -1) {
        return priorityA - priorityB;
      }
      
      // Se solo uno ha priorità, mettilo prima
      if (priorityA !== -1) return -1;
      if (priorityB !== -1) return 1;
      
      // Se nessuno ha priorità specifica, ordina alfabeticamente
      return fileNameA.localeCompare(fileNameB);
    });

    return { priorityTests, regularTests };
  }

  /**
   * Ordina i test di integrazione per dipendenze
   */
  sortIntegrationTestsByDependency(integrationTests) {
    // Ordine di dipendenza per i test di integrazione
    const dependencyOrder = [
      'database',     // Database per primo
      'health',       // Health check
      'firewall',     // Core functionality
      'monitoring',   // Monitoring
      'policies',     // Policies
      'admin'         // Admin per ultimo
    ];

    const categorizedTests = {
      database: [],
      health: [],
      firewall: [],
      monitoring: [],
      policies: [],
      admin: [],
      other: []
    };

    // Categorizza i test per dipendenza
    for (const test of integrationTests) {
      const testPath = test.path.toLowerCase();
      let categorized = false;

      for (const category of dependencyOrder) {
        if (testPath.includes(category)) {
          categorizedTests[category].push(test);
          categorized = true;
          break;
        }
      }

      if (!categorized) {
        categorizedTests.other.push(test);
      }
    }

    // Ordina ogni categoria alfabeticamente
    Object.keys(categorizedTests).forEach(category => {
      categorizedTests[category].sort((a, b) => a.path.localeCompare(b.path));
    });

    // Combina nell'ordine di dipendenza
    return [
      ...categorizedTests.database,
      ...categorizedTests.health,
      ...categorizedTests.firewall,
      ...categorizedTests.monitoring,
      ...categorizedTests.policies,
      ...categorizedTests.admin,
      ...categorizedTests.other
    ];
  }

  /**
   * Shard function personalizzata per parallelizzazione
   */
  shard(tests, options) {
    // Se non è richiesto lo sharding, ritorna tutti i test
    if (!options.shard) {
      return tests;
    }

    const { shardIndex, shardCount } = options.shard;
    
    // Distribuisce i test tra gli shard mantenendo l'ordine
    const testsPerShard = Math.ceil(tests.length / shardCount);
    const startIndex = shardIndex * testsPerShard;
    const endIndex = startIndex + testsPerShard;
    
    return tests.slice(startIndex, endIndex);
  }

  /**
   * Funzione di utilità per debugging del sequencer
   */
  getTestCategories(tests) {
    const categories = {
      unit: { critical: [], regular: [] },
      integration: { database: [], health: [], firewall: [], monitoring: [], policies: [], admin: [], other: [] },
      other: []
    };

    for (const test of tests) {
      const testPath = test.path;
      const fileName = path.basename(testPath);

      if (this.isUnitTest(testPath)) {
        const criticalFiles = ['auth.test.js', 'errorHandler.test.js', 'rateLimit.test.js', 'validation.test.js', 'logger.test.js', 'helpers.test.js'];
        
        if (criticalFiles.includes(fileName)) {
          categories.unit.critical.push(fileName);
        } else {
          categories.unit.regular.push(fileName);
        }
      } else if (this.isIntegrationTest(testPath)) {
        const pathLower = testPath.toLowerCase();
        
        if (pathLower.includes('database')) categories.integration.database.push(fileName);
        else if (pathLower.includes('health')) categories.integration.health.push(fileName);
        else if (pathLower.includes('firewall')) categories.integration.firewall.push(fileName);
        else if (pathLower.includes('monitoring')) categories.integration.monitoring.push(fileName);
        else if (pathLower.includes('policies')) categories.integration.policies.push(fileName);
        else if (pathLower.includes('admin')) categories.integration.admin.push(fileName);
        else categories.integration.other.push(fileName);
      } else {
        categories.other.push(fileName);
      }
    }

    return categories;
  }
}

module.exports = CustomTestSequencer;