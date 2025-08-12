const logger = require('../utils/logger');

/**
 * Async handler wrapper to catch errors in async route handlers
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Express middleware function
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    const startTime = Date.now();
    
    // Add request context for better error tracking
    const requestContext = {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.id || req.headers['x-request-id'],
      userId: req.user?.id,
      timestamp: new Date().toISOString()
    };

    Promise.resolve(fn(req, res, next))
      .then((result) => {
        // Log successful async operations (optional, for debugging)
        const duration = Date.now() - startTime;
        if (duration > 1000) { // Log slow operations
          logger.warn('Slow async operation detected', {
            ...requestContext,
            duration,
            operation: fn.name || 'anonymous'
          });
        }
        return result;
      })
      .catch((error) => {
        // Enhanced error logging with context
        logger.error('Async handler error', {
          ...requestContext,
          error: {
            message: error.message,
            stack: error.stack,
            name: error.name,
            code: error.code,
            status: error.status || error.statusCode
          },
          duration: Date.now() - startTime,
          operation: fn.name || 'anonymous'
        });

        // Add request context to error for downstream handlers
        error.requestContext = requestContext;
        
        // Pass error to Express error handler
        next(error);
      });
  };
};

/**
 * Async handler with timeout support
 * @param {Function} fn - Async function to wrap
 * @param {number} timeoutMs - Timeout in milliseconds (default: 30000)
 * @returns {Function} Express middleware function
 */
const asyncHandlerWithTimeout = (fn, timeoutMs = 30000) => {
  return asyncHandler(async (req, res, next) => {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    try {
      const result = await Promise.race([
        fn(req, res, next),
        timeoutPromise
      ]);
      return result;
    } catch (error) {
      if (error.message.includes('timed out')) {
        error.status = 408; // Request Timeout
        error.code = 'OPERATION_TIMEOUT';
      }
      throw error;
    }
  });
};

/**
 * Batch async handler for processing multiple operations
 * @param {Function} fn - Async function that returns array of promises
 * @param {Object} options - Batch processing options
 * @returns {Function} Express middleware function
 */
const batchAsyncHandler = (fn, options = {}) => {
  const {
    maxConcurrency = 5,
    failFast = false,
    timeout = 60000
  } = options;

  return asyncHandler(async (req, res, next) => {
    const operations = await fn(req, res, next);
    
    if (!Array.isArray(operations)) {
      throw new Error('Batch handler function must return array of promises');
    }

    const results = [];
    const errors = [];
    
    // Process operations in batches
    for (let i = 0; i < operations.length; i += maxConcurrency) {
      const batch = operations.slice(i, i + maxConcurrency);
      
      const batchPromises = batch.map(async (operation, index) => {
        try {
          const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Batch operation timeout')), timeout);
          });
          
          const result = await Promise.race([operation, timeoutPromise]);
          return { success: true, result, index: i + index };
        } catch (error) {
          const errorResult = { success: false, error, index: i + index };
          
          if (failFast) {
            throw error;
          }
          
          return errorResult;
        }
      });

      const batchResults = await Promise.all(batchPromises);
      
      batchResults.forEach(result => {
        if (result.success) {
          results.push(result);
        } else {
          errors.push(result);
        }
      });
    }

    // Attach results to request for downstream processing
    req.batchResults = {
      successful: results,
      failed: errors,
      totalCount: operations.length,
      successCount: results.length,
      errorCount: errors.length
    };

    // If all operations failed and failFast is enabled, throw error
    if (failFast && errors.length > 0) {
      const error = new Error('Batch operation failed');
      error.batchErrors = errors;
      error.status = 500;
      throw error;
    }
  });
};

/**
 * Async handler with retry logic
 * @param {Function} fn - Async function to wrap
 * @param {Object} retryOptions - Retry configuration
 * @returns {Function} Express middleware function
 */
const retryAsyncHandler = (fn, retryOptions = {}) => {
  const {
    maxRetries = 3,
    retryDelay = 1000,
    exponentialBackoff = true,
    retryCondition = (error) => error.code === 'ECONNRESET' || error.status >= 500
  } = retryOptions;

  return asyncHandler(async (req, res, next) => {
    let lastError;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await fn(req, res, next);
        
        // Log retry success if this wasn't the first attempt
        if (attempt > 0) {
          logger.info('Retry successful', {
            attempt,
            maxRetries,
            requestId: req.id,
            operation: fn.name
          });
        }
        
        return result;
      } catch (error) {
        lastError = error;
        
        // Check if we should retry
        if (attempt < maxRetries && retryCondition(error)) {
          const delay = exponentialBackoff 
            ? retryDelay * Math.pow(2, attempt)
            : retryDelay;
          
          logger.warn('Operation failed, retrying', {
            attempt: attempt + 1,
            maxRetries,
            delay,
            error: error.message,
            requestId: req.id,
            operation: fn.name
          });
          
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
        
        // No more retries or retry condition not met
        break;
      }
    }
    
    // All retries exhausted
    logger.error('All retry attempts exhausted', {
      maxRetries,
      finalError: lastError.message,
      requestId: req.id,
      operation: fn.name
    });
    
    throw lastError;
  });
};

/**
 * Create async handler with custom error processing
 * @param {Object} options - Handler options
 * @returns {Function} Configured async handler
 */
const createAsyncHandler = (options = {}) => {
  const {
    timeout,
    retries,
    logSlowOperations = true,
    slowOperationThreshold = 1000,
    errorTransformer = (error) => error
  } = options;

  return (fn) => {
    let handler = asyncHandler;
    
    // Apply timeout if specified
    if (timeout) {
      const originalFn = fn;
      fn = async (req, res, next) => {
        return asyncHandlerWithTimeout(originalFn, timeout)(req, res, next);
      };
    }
    
    // Apply retry logic if specified
    if (retries) {
      const originalFn = fn;
      fn = async (req, res, next) => {
        return retryAsyncHandler(originalFn, retries)(req, res, next);
      };
    }
    
    return (req, res, next) => {
      const startTime = Date.now();
      
      Promise.resolve(fn(req, res, next))
        .then((result) => {
          const duration = Date.now() - startTime;
          
          if (logSlowOperations && duration > slowOperationThreshold) {
            logger.warn('Slow operation detected', {
              duration,
              threshold: slowOperationThreshold,
              operation: fn.name,
              requestId: req.id
            });
          }
          
          return result;
        })
        .catch((error) => {
          // Apply error transformation
          const transformedError = errorTransformer(error);
          
          logger.error('Async operation failed', {
            error: transformedError.message,
            operation: fn.name,
            requestId: req.id,
            duration: Date.now() - startTime
          });
          
          next(transformedError);
        });
    };
  };
};

/**
 * Async handler for database operations with transaction support
 * @param {Function} fn - Database operation function
 * @param {Object} options - Transaction options
 * @returns {Function} Express middleware function
 */
const dbAsyncHandler = (fn, options = {}) => {
  const { autoTransaction = true, isolationLevel } = options;
  
  return asyncHandler(async (req, res, next) => {
    if (!autoTransaction) {
      return await fn(req, res, next);
    }
    
    const { sequelize } = require('../config/database');
    const transaction = await sequelize.transaction({
      isolationLevel: isolationLevel || sequelize.Transaction.ISOLATION_LEVELS.READ_COMMITTED
    });
    
    try {
      // Add transaction to request for use in the handler
      req.transaction = transaction;
      
      const result = await fn(req, res, next);
      
      await transaction.commit();
      
      logger.debug('Database transaction committed', {
        requestId: req.id,
        operation: fn.name
      });
      
      return result;
    } catch (error) {
      await transaction.rollback();
      
      logger.error('Database transaction rolled back', {
        error: error.message,
        requestId: req.id,
        operation: fn.name
      });
      
      throw error;
    }
  });
};

module.exports = {
  asyncHandler,
  asyncHandlerWithTimeout,
  batchAsyncHandler,
  retryAsyncHandler,
  createAsyncHandler,
  dbAsyncHandler
};