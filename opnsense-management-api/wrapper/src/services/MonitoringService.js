const axios = require('axios');
const logger = require('../utils/logger');
const { opnsenseConfig, opnsenseApi } = require('../config/opnsense');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const AlertService = require('./AlertService');
const User = require('../models/User');

class MonitoringService {
  constructor(user = null) {
    this.user = user;
    // Fix: usa opnsenseConfig.baseURL invece di apiUrl
    this.baseUrl = opnsenseConfig.baseURL;
    this.apiKey = opnsenseConfig.apiKey;
    this.apiSecret = opnsenseConfig.apiSecret;
    this.alertService = new AlertService(user);
    this.cacheTimeout = parseInt(process.env.OPNSENSE_CACHE_TIMEOUT || '60', 10);
    this.maxRetries = parseInt(process.env.OPNSENSE_RETRIES || '3', 10);
    this.requestTimeout = parseInt(process.env.OPNSENSE_TIMEOUT || '30000', 10);
    this.rateLimitMap = new Map();
    this.thresholds = {
      cpu_usage: parseInt(process.env.CPU_THRESHOLD || '90', 10),
      memory_usage: parseInt(process.env.MEMORY_THRESHOLD || '85', 10),
      disk_usage: parseInt(process.env.DISK_THRESHOLD || '95', 10),
      network_bytes_threshold: parseInt(process.env.NETWORK_THRESHOLD || '1000000000', 10)
    };
  }

  /**
   * Rate limiting check
   * @param {string} operation - Operation identifier
   * @param {number} maxRequests - Max requests per minute
   * @returns {boolean} True if allowed
   * @private
   */
  checkRateLimit(operation, maxRequests = 60) {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    
    if (!this.rateLimitMap.has(operation)) {
      this.rateLimitMap.set(operation, []);
    }
    
    const requests = this.rateLimitMap.get(operation);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(timestamp => now - timestamp < windowMs);
    
    if (validRequests.length >= maxRequests) {
      logger.warn('Rate limit exceeded', { operation, requests_count: validRequests.length });
      return false;
    }
    
    validRequests.push(now);
    this.rateLimitMap.set(operation, validRequests);
    return true;
  }

  /**
   * Safely get from cache with error handling
   * @param {string} key - Cache key
   * @returns {any|null} Cached value or null
   * @private
   */
  async safeGetCache(key) {
    try {
      return await cache.get(key);
    } catch (error) {
      logger.warn('Cache get failed', { key, error: error.message });
      return null;
    }
  }

  /**
   * Safely set cache with error handling
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {number} ttl - Time to live
   * @private
   */
  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttl);
    } catch (error) {
      logger.warn('Cache set failed', { key, error: error.message });
    }
  }

  /**
   * Make API request usando l'instance configurato di opnsense
   * @param {string} endpoint - API endpoint
   * @param {Object} params - Request parameters
   * @param {string} operation - Operation name for rate limiting
   * @returns {Object} API response
   * @private
   */
  async makeApiRequest(endpoint, params = {}, operation = 'default') {
    // Check rate limit
    if (!this.checkRateLimit(operation)) {
      throw new Error(`Rate limit exceeded for operation: ${operation}`);
    }

    try {
      const response = await opnsenseApi.get(endpoint, { params });
      return response.data;
    } catch (error) {
      logger.error('OPNsense API request failed', {
        endpoint,
        operation,
        error: error.message,
        status: error.response?.status
      });
      throw error;
    }
  }

  /**
   * Collect system metrics from OPNsense
   * @returns {Object} System metrics
   */
  async collectSystemMetrics() {
    try {
      const cacheKey = 'system_metrics';
      const cachedMetrics = await this.safeGetCache(cacheKey);

      if (cachedMetrics) {
        logger.debug('Returning cached system metrics', { cache_key: cacheKey });
        return cachedMetrics;
      }

      // Usa endpoints OPNsense reali
      const data = await this.makeApiRequest('/api/core/system/getSystemInformation', {}, 'system_metrics');
      
      // Adatta i dati alla struttura OPNsense reale
      const metrics = {
        cpu_usage: this.extractCpuUsage(data),
        memory_usage: this.extractMemoryUsage(data),
        disk_usage: this.extractDiskUsage(data),
        uptime: this.extractUptime(data),
        timestamp: new Date(),
      };

      // Validate metrics
      if (isNaN(metrics.cpu_usage) || isNaN(metrics.memory_usage) || isNaN(metrics.disk_usage)) {
        throw new Error('Invalid metrics received from API');
      }

      // Check thresholds and create alerts if necessary
      await this.checkSystemThresholds(metrics);

      // Cache the result
      await this.safeSetCache(cacheKey, metrics, this.cacheTimeout);

      return metrics;
    } catch (error) {
      logger.error('Failed to collect system metrics', { error: error.message });
      if (this.alertService) {
        await this.alertService.createSystemAlert({
          type: 'system_error',
          message: `Failed to collect system metrics: ${error.message}`,
          severity: 'high',
          source: 'monitoring',
          metadata: { error_type: 'api_failure', endpoint: '/api/core/system/getSystemInformation' }
        }).catch(alertError => {
          logger.error('Failed to create system alert', { error: alertError.message });
        });
      }
      throw error;
    }
  }

  /**
   * Extract CPU usage from OPNsense system data
   * @param {Object} data - System data from OPNsense
   * @returns {number} CPU usage percentage
   * @private
   */
  extractCpuUsage(data) {
    // OPNsense può avere diversi formati per CPU usage
    if (data.cpu && typeof data.cpu.usage === 'number') {
      return Math.min(100, Math.max(0, data.cpu.usage));
    }
    if (data.system && typeof data.system.cpu_usage === 'number') {
      return Math.min(100, Math.max(0, data.system.cpu_usage));
    }
    // Fallback: calcola da load average se disponibile
    if (data.system && data.system.load_avg) {
      const loadAvg = parseFloat(data.system.load_avg[0] || 0);
      const cpuCores = parseInt(data.system.cpu_count || 1);
      return Math.min(100, Math.max(0, (loadAvg / cpuCores) * 100));
    }
    return 0;
  }

  /**
   * Extract memory usage from OPNsense system data
   * @param {Object} data - System data from OPNsense
   * @returns {number} Memory usage percentage
   * @private
   */
  extractMemoryUsage(data) {
    if (data.memory) {
      const total = parseInt(data.memory.total || 0);
      const used = parseInt(data.memory.used || 0);
      if (total > 0) {
        return Math.min(100, Math.max(0, (used / total) * 100));
      }
    }
    if (data.system && data.system.memory) {
      const total = parseInt(data.system.memory.total || 0);
      const free = parseInt(data.system.memory.free || 0);
      if (total > 0) {
        const used = total - free;
        return Math.min(100, Math.max(0, (used / total) * 100));
      }
    }
    return 0;
  }

  /**
   * Extract disk usage from OPNsense system data
   * @param {Object} data - System data from OPNsense
   * @returns {number} Disk usage percentage
   * @private
   */
  extractDiskUsage(data) {
    if (data.disk) {
      const total = parseInt(data.disk.total || 0);
      const used = parseInt(data.disk.used || 0);
      if (total > 0) {
        return Math.min(100, Math.max(0, (used / total) * 100));
      }
    }
    if (data.system && data.system.disk) {
      const usage = parseFloat(data.system.disk.usage_percent || 0);
      return Math.min(100, Math.max(0, usage));
    }
    return 0;
  }

  /**
   * Extract uptime from OPNsense system data
   * @param {Object} data - System data from OPNsense
   * @returns {number} Uptime in seconds
   * @private
   */
  extractUptime(data) {
    if (data.system && typeof data.system.uptime === 'number') {
      return Math.max(0, data.system.uptime);
    }
    if (data.uptime && typeof data.uptime === 'number') {
      return Math.max(0, data.uptime);
    }
    return 0;
  }

  /**
   * Collect network interface metrics from OPNsense
   * @param {string} interfaceName - Optional interface name to filter
   * @returns {Array} Network interface metrics
   */
  async collectNetworkMetrics(interfaceName = null) {
    try {
      // Validate interface name if provided
      if (interfaceName && !/^[a-zA-Z0-9_.-]+$/.test(interfaceName)) {
        throw new Error('Invalid interface name format');
      }

      const cacheKey = `network_metrics_${interfaceName || 'all'}`;
      const cachedMetrics = await this.safeGetCache(cacheKey);

      if (cachedMetrics) {
        logger.debug('Returning cached network metrics', { cache_key: cacheKey });
        return cachedMetrics;
      }

      // Usa endpoint OPNsense reale per le interfacce
      const data = await this.makeApiRequest('/api/interfaces/overview/get', {}, 'network_metrics');
      
      const interfaces = data.interfaces || {};
      const metrics = [];

      for (const [name, intf] of Object.entries(interfaces)) {
        // Se specificato un'interfaccia, filtra
        if (interfaceName && name !== interfaceName) {
          continue;
        }

        if (intf && intf.statistics) {
          metrics.push({
            interface: name,
            bytes_in: parseInt(intf.statistics.bytes_received || 0),
            bytes_out: parseInt(intf.statistics.bytes_transmitted || 0),
            packets_in: parseInt(intf.statistics.packets_received || 0),
            packets_out: parseInt(intf.statistics.packets_transmitted || 0),
            errors_in: parseInt(intf.statistics.errors_in || 0),
            errors_out: parseInt(intf.statistics.errors_out || 0),
            status: intf.status || 'unknown',
            timestamp: new Date(),
          });
        }
      }

      // Se interfaccia specificata ma non trovata
      if (interfaceName && metrics.length === 0) {
        throw new Error(`Interface ${interfaceName} not found`);
      }

      // Check thresholds and create alerts if necessary
      await this.checkNetworkThresholds(metrics);

      // Cache the result
      await this.safeSetCache(cacheKey, metrics, this.cacheTimeout);

      return metrics;
    } catch (error) {
      logger.error('Failed to collect network metrics', {
        error: error.message,
        interface: interfaceName,
      });
      if (this.alertService) {
        await this.alertService.createSystemAlert({
          type: 'network_error',
          message: `Failed to collect network metrics: ${error.message}`,
          severity: 'medium',
          source: 'monitoring',
          metadata: { 
            error_type: 'api_failure', 
            endpoint: '/api/interfaces/overview/get',
            interface: interfaceName 
          }
        }).catch(alertError => {
          logger.error('Failed to create network alert', { error: alertError.message });
        });
      }
      throw error;
    }
  }

  /**
   * Check system thresholds and generate alerts
   * @param {Object} metrics - System metrics
   * @private
   */
  async checkSystemThresholds(metrics) {
    try {
      const alertPromises = [];

      if (metrics.cpu_usage > this.thresholds.cpu_usage) {
        alertPromises.push(
          this.alertService.createSystemAlert({
            type: 'performance_issue',
            message: `High CPU usage detected: ${metrics.cpu_usage}% (threshold: ${this.thresholds.cpu_usage}%)`,
            severity: metrics.cpu_usage > 95 ? 'critical' : 'high',
            source: 'monitoring',
            metadata: { 
              cpu_usage: metrics.cpu_usage,
              threshold: this.thresholds.cpu_usage,
              metric_type: 'cpu'
            },
          })
        );
      }

      if (metrics.memory_usage > this.thresholds.memory_usage) {
        alertPromises.push(
          this.alertService.createSystemAlert({
            type: 'performance_issue',
            message: `High memory usage detected: ${metrics.memory_usage}% (threshold: ${this.thresholds.memory_usage}%)`,
            severity: metrics.memory_usage > 95 ? 'critical' : 'high',
            source: 'monitoring',
            metadata: { 
              memory_usage: metrics.memory_usage,
              threshold: this.thresholds.memory_usage,
              metric_type: 'memory'
            },
          })
        );
      }

      if (metrics.disk_usage > this.thresholds.disk_usage) {
        alertPromises.push(
          this.alertService.createSystemAlert({
            type: 'performance_issue',
            message: `High disk usage detected: ${metrics.disk_usage}% (threshold: ${this.thresholds.disk_usage}%)`,
            severity: 'critical',
            source: 'monitoring',
            metadata: { 
              disk_usage: metrics.disk_usage,
              threshold: this.thresholds.disk_usage,
              metric_type: 'disk'
            },
          })
        );
      }

      // Execute all alert creations in parallel
      await Promise.allSettled(alertPromises);
    } catch (error) {
      logger.error('Failed to check system thresholds', {
        error: error.message,
        metrics,
      });
    }
  }

  /**
   * Check network thresholds and generate alerts
   * @param {Array} metrics - Network metrics
   * @private
   */
  async checkNetworkThresholds(metrics) {
    try {
      const alertPromises = [];

      for (const metric of metrics) {
        // Check for high traffic
        if (metric.bytes_in > this.thresholds.network_bytes_threshold || 
            metric.bytes_out > this.thresholds.network_bytes_threshold) {
          alertPromises.push(
            this.alertService.createSystemAlert({
              type: 'network_anomaly',
              message: `High network traffic on interface ${metric.interface}: ${metric.bytes_in} bytes in, ${metric.bytes_out} bytes out`,
              severity: 'high',
              source: 'monitoring',
              metadata: {
                interface: metric.interface,
                bytes_in: metric.bytes_in,
                bytes_out: metric.bytes_out,
                threshold: this.thresholds.network_bytes_threshold,
                metric_type: 'network_traffic'
              },
            })
          );
        }

        // Check for interface errors
        if (metric.errors_in > 100 || metric.errors_out > 100) {
          alertPromises.push(
            this.alertService.createSystemAlert({
              type: 'network_anomaly',
              message: `High error rate on interface ${metric.interface}: ${metric.errors_in} errors in, ${metric.errors_out} errors out`,
              severity: 'medium',
              source: 'monitoring',
              metadata: {
                interface: metric.interface,
                errors_in: metric.errors_in,
                errors_out: metric.errors_out,
                metric_type: 'network_errors'
              },
            })
          );
        }
      }

      // Execute all alert creations in parallel
      await Promise.allSettled(alertPromises);
    } catch (error) {
      logger.error('Failed to check network thresholds', {
        error: error.message,
        metrics,
      });
    }
  }

  /**
   * Get monitoring health status
   * @returns {Object} Health status
   */
  async getHealthStatus() {
    try {
      const startTime = Date.now();
      
      // Test API connectivity
      let apiStatus = 'healthy';
      let apiResponseTime = 0;
      
      try {
        const apiStart = Date.now();
        await this.makeApiRequest('/api/core/system/status', {}, 'health_check');
        apiResponseTime = Date.now() - apiStart;
      } catch (error) {
        apiStatus = 'unhealthy';
        logger.warn('API health check failed', { error: error.message });
      }

      // Test cache connectivity
      let cacheStatus = 'healthy';
      try {
        await this.safeSetCache('health_check', Date.now(), 10);
        await this.safeGetCache('health_check');
      } catch (error) {
        cacheStatus = 'unhealthy';
        logger.warn('Cache health check failed', { error: error.message });
      }

      const totalResponseTime = Date.now() - startTime;

      const health = {
        status: apiStatus === 'healthy' && cacheStatus === 'healthy' ? 'healthy' : 'degraded',
        timestamp: new Date(),
        components: {
          opnsense_api: {
            status: apiStatus,
            response_time_ms: apiResponseTime
          },
          cache: {
            status: cacheStatus
          }
        },
        total_response_time_ms: totalResponseTime,
        rate_limit_status: {
          active_operations: this.rateLimitMap.size,
          total_requests_last_minute: Array.from(this.rateLimitMap.values())
            .flat()
            .filter(timestamp => Date.now() - timestamp < 60000)
            .length
        }
      };

      return health;
    } catch (error) {
      logger.error('Failed to get health status', { error: error.message });
      return {
        status: 'unhealthy',
        timestamp: new Date(),
        error: error.message
      };
    }
  }

  /**
   * Export metrics in formato compatibile con il monitoring
   * @returns {Object} Formatted metrics
   */
  async exportMetrics() {
    try {
      // Verify user has appropriate role if provided
      if (this.user) {
        const user = await User.findByPk(this.user.id);
        if (!user) {
          throw new Error('User not found');
        }
        if (!['admin', 'operator', 'viewer'].includes(user.role)) {
          throw new Error('User does not have permission to export metrics');
        }
      }

      const [systemMetrics, networkMetrics] = await Promise.all([
        this.collectSystemMetrics().catch(error => {
          logger.warn('System metrics collection failed for export', { error: error.message });
          return null;
        }),
        this.collectNetworkMetrics().catch(error => {
          logger.warn('Network metrics collection failed for export', { error: error.message });
          return null;
        })
      ]);

      const exportedMetrics = {
        system: systemMetrics,
        network: networkMetrics,
        timestamp: new Date(),
        collector: 'opnsense-monitoring-service'
      };

      logger.info('Metrics exported successfully', {
        user_id: this.user?.id,
        has_system_metrics: !!systemMetrics,
        has_network_metrics: !!networkMetrics && networkMetrics.length > 0
      });

      return exportedMetrics;
    } catch (error) {
      logger.error('Failed to export metrics', {
        error: error.message,
        user_id: this.user?.id,
      });
      throw error;
    }
  }
}

module.exports = MonitoringService;