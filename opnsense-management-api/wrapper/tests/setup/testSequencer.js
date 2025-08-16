// tests/setup/testSequencer.js
const Sequencer = require('@jest/test-sequencer').default;

class CustomTestSequencer extends Sequencer {
  /**
   * Sort test files to run unit tests before integration tests
   * @param {Array} tests - Array of test files
   * @returns {Array} Sorted array of test files
   */
  sort(tests) {
    // Separate tests by type
    const unitTests = [];
    const integrationTests = [];
    const otherTests = [];
    
    tests.forEach(test => {
      const testPath = test.path;
      
      if (testPath.includes('/unit/')) {
        unitTests.push(test);
      } else if (testPath.includes('/integration/')) {
        integrationTests.push(test);
      } else {
        otherTests.push(test);
      }
    });
    
    // Sort each category alphabetically
    const sortAlphabetically = (a, b) => a.path.localeCompare(b.path);
    
    unitTests.sort(sortAlphabetically);
    integrationTests.sort(sortAlphabetically);
    otherTests.sort(sortAlphabetically);
    
    // Prioritize critical files within unit tests
    const criticalFiles = [
      'auth.test.js',
      'errorHandler.test.js',
      'rateLimit.test.js'
    ];
    
    const priorityUnitTests = [];
    const regularUnitTests = [];
    
    unitTests.forEach(test => {
      const fileName = test.path.split('/').pop();
      if (criticalFiles.includes(fileName)) {
        priorityUnitTests.push(test);
      } else {
        regularUnitTests.push(test);
      }
    });
    
    // Return tests in order: priority unit -> regular unit -> other -> integration
    return [
      ...priorityUnitTests,
      ...regularUnitTests, 
      ...otherTests,
      ...integrationTests
    ];
  }
}

module.exports = CustomTestSequencer;