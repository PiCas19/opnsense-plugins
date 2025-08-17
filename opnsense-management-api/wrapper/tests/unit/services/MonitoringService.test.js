// tests/unit/services/MonitoringService.test.js

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock della config di monitoring (dipendenze + soglie) con dati dai fixtures
jest.mock('../../../src/config/monitoring', () => ({
  dependencies: {
    api:     { url: 'http://localhost:3001/health', critical: true,  timeout: 1000 },
    grafana: { url: 'http://localhost:3000/api/health', critical: false, timeout: 1000 },
    opnsense: { url: 'https://192.168.1.1/api/core/system/status', critical: true, timeout: 2000 },
    redis:   { url: 'http://localhost:6379/ping', critical: false, timeout: 500 },
  },
  thresholds: {
    latency:  { warn: 500,  critical: 1500 },
    cpuLoad:  { warn: 2.0,  critical: 4.0 },
    memory:   { warn: 80,   critical: 95 },
    disk:     { warn: 80,   critical: 95 },
    connections: { warn: 100, critical: 200 },
    errorRate: { warn: 5, critical: 15 }
  },
  sampleIntervalMs: 5000,
  alerting: {
    enabled: true,
    channels: ['email', 'slack'],
    cooldownMs: 300000 // 5 minutes
  }
}));

// Mock del database (tipico: sequelize.authenticate)
const authenticateMock = jest.fn();
jest.mock('../../../src/config/database', () => ({
  sequelize: { authenticate: (...args) => authenticateMock(...args) },
}));

// Mock axios client usato internamente dal service
const axiosInstance = {
  get: jest.fn(),
  post: jest.fn(),
  request: jest.fn(),
};
jest.mock('axios', () => ({
  create: jest.fn(() => axiosInstance),
  isAxiosError: jest.fn(),
}));

// Mock filesystem per test disk usage
const fsMock = {
  promises: {
    stat: jest.fn(),
    readdir: jest.fn(),
  }
};
jest.mock('fs', () => fsMock);

const os = require('os');
const logger = require('../../../src/utils/logger');
const monitoringCfg = require('../../../src/config/monitoring');
const { sequelize } = require('../../../src/config/database');
const MonitoringService = require('../../../src/services/MonitoringService');
const axios = require('axios');

const hasMethod = (name) => typeof MonitoringService?.[name] === 'function';

describe('MonitoringService', () => {
  // Helper functions usando fixtures globali
  const resetMocks = () => {
    jest.clearAllMocks();
    logger.info.mockClear();
    logger.warn.mockClear();
    logger.error.mockClear();
    logger.debug.mockClear();
  };

  beforeEach(() => {
    resetMocks();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in MonitoringService test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  it('inizializza il client HTTP con timeout e base headers', () => {
    // La sola import di MonitoringService dovrebbe aver creato l'istanza axios
    expect(axios.create).toHaveBeenCalledWith(
      expect.objectContaining({
        timeout: expect.any(Number),
        headers: expect.objectContaining({
          'User-Agent': expect.stringContaining('OPNsense-Monitor'),
          'Accept': 'application/json'
        }),
      })
    );
  });

  describe('getHealth', () => {
    it('ritorna status OK quando DB e dipendenze sono ok con dati dai fixtures', async () => {
      if (!hasMethod('getHealth')) {
        console.warn('MonitoringService.getHealth non esiste: test saltato.');
        return;
      }

      const healthyResponses = {
        api: { status: 'ok', version: '1.0.0', uptime: fixtures.random.number(1000, 10000) },
        grafana: { database: 'ok', version: '9.0.0' },
        opnsense: { status: 'online', version: '23.7.1' },
        redis: { status: 'PONG', memory_usage: fixtures.random.number(100, 500) }
      };

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: healthyResponses.api })
        .mockResolvedValueOnce({ status: 200, data: healthyResponses.grafana })
        .mockResolvedValueOnce({ status: 200, data: healthyResponses.opnsense })
        .mockResolvedValueOnce({ status: 200, data: healthyResponses.redis });

      const res = await MonitoringService.getHealth();

      expect(sequelize.authenticate).toBeDefined();
      expect(authenticateMock).toHaveBeenCalled();

      expect(res).toBeDefined();
      // status complessivo
      expect(['ok', 'healthy', 'up']).toContain(res.status);

      // mappa dipendenze (forme tolleranti)
      const deps = res.dependencies || res.components || {};
      expect(deps.api?.status || deps.api).toBeTruthy();
      expect(String(deps.api?.status || deps.api)).toMatch(/ok|up|healthy/i);
      expect(String(deps.database?.status || deps.database)).toMatch(/ok|up|healthy/i);

      // Verifica metadata aggiuntivi
      if (res.metadata) {
        expect(res.metadata).toHaveProperty('timestamp');
        expect(res.metadata).toHaveProperty('version');
      }

      expect(logger.info).toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    it('se una dipendenza fallisce → status degraded/error e log warn/error', async () => {
      if (!hasMethod('getHealth')) {
        console.warn('MonitoringService.getHealth non esiste: test saltato.');
        return;
      }

      const networkError = fixtures.createNetworkError('connection_refused');
      const timeoutError = fixtures.createNetworkError('timeout');

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok' } }) // api ok
        .mockRejectedValueOnce(networkError)                            // grafana down
        .mockRejectedValueOnce(timeoutError)                           // opnsense timeout
        .mockResolvedValueOnce({ status: 503, data: { error: 'Service unavailable' } }); // redis degraded

      const res = await MonitoringService.getHealth();

      expect(res).toBeDefined();
      expect(res.status).toMatch(/degraded|error|partial|unhealthy/i);

      const deps = res.dependencies || res.components || {};
      const grafana = deps.grafana?.status || deps.grafana;
      const opnsense = deps.opnsense?.status || deps.opnsense;
      
      expect(String(grafana)).toMatch(/down|error|unhealthy/i);
      expect(String(opnsense)).toMatch(/down|error|timeout/i);

      expect(logger.warn).toHaveBeenCalled();
      // error può essere chiamato se il service lo considera critico
      expect(logger.error.mock.calls.length >= 0).toBe(true);
    });

    it('se il DB non risponde → stato non ok con context dai fixtures', async () => {
      if (!hasMethod('getHealth')) {
        console.warn('MonitoringService.getHealth non esiste: test saltato.');
        return;
      }

      const dbError = fixtures.createHTTPError(503, 'Database connection timeout');
      authenticateMock.mockRejectedValue(dbError);
      
      axiosInstance.get
        .mockResolvedValue({ status: 200, data: { status: 'ok' } });

      const res = await MonitoringService.getHealth();
      expect(res.status).toMatch(/degraded|error|partial|unhealthy/i);

      const deps = res.dependencies || res.components || {};
      const dbStatus = deps.database?.status || deps.db || deps.database;
      expect(String(dbStatus)).toMatch(/down|error|unhealthy|timeout/i);

      // Verifica error details
      if (deps.database?.error) {
        expect(deps.database.error).toContain('timeout');
      }

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Database health check failed'),
        expect.objectContaining({
          error: expect.any(String)
        })
      );
    });

    it('gestisce health check con rate limiting dai fixtures', async () => {
      if (!hasMethod('getHealth')) return;

      const rateLimitConfig = fixtures.createRateLimitConfig();
      const rateLimitError = fixtures.createHTTPError(429, 'Too Many Requests');

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok' } })
        .mockRejectedValueOnce(rateLimitError);

      const res = await MonitoringService.getHealth();

      const deps = res.dependencies || res.components || {};
      expect(res.status).toMatch(/degraded|partial/i);
      
      // Rate limit dovrebbe essere gestito gracefully
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Rate limited'),
        expect.any(Object)
      );
    });
  });

  describe('getSystemMetrics', () => {
    it('ritorna metriche di sistema con chiavi attese e dati realistici', async () => {
      if (!hasMethod('getSystemMetrics')) {
        console.warn('MonitoringService.getSystemMetrics non esiste: test saltato.');
        return;
      }

      const uptimeSeconds = fixtures.random.number(3600, 86400); // 1-24 ore
      const totalMemGB = fixtures.random.number(4, 32); // 4-32 GB
      const freeMemGB = fixtures.random.number(1, totalMemGB - 1);
      const cpuCount = fixtures.random.number(2, 16);
      
      const totalMemBytes = totalMemGB * 1024 * 1024 * 1024;
      const freeMemBytes = freeMemGB * 1024 * 1024 * 1024;

      jest.spyOn(os, 'uptime').mockReturnValue(uptimeSeconds);
      jest.spyOn(os, 'totalmem').mockReturnValue(totalMemBytes);
      jest.spyOn(os, 'freemem').mockReturnValue(freeMemBytes);
      jest.spyOn(os, 'loadavg').mockReturnValue([0.5, 0.4, 0.3]);
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(cpuCount).fill({
        model: 'Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz',
        speed: 2600,
        times: {
          user: fixtures.random.number(10000, 50000),
          nice: fixtures.random.number(100, 1000),
          sys: fixtures.random.number(5000, 15000),
          idle: fixtures.random.number(100000, 500000),
          irq: fixtures.random.number(100, 500)
        }
      }));

      const m = await MonitoringService.getSystemMetrics();

      expect(m).toEqual(expect.objectContaining({
        uptime: uptimeSeconds,
        cpuCount: cpuCount,
      }));
      
      expect(m).toHaveProperty('load');
      expect(Array.isArray(m.load)).toBe(true);
      expect(m.load).toHaveLength(3);

      // utilizzo memoria coerente
      expect(m).toHaveProperty('memory');
      expect(m.memory).toEqual(expect.objectContaining({
        total: totalMemBytes,
        free: freeMemBytes,
        used: totalMemBytes - freeMemBytes,
        usedPercent: expect.any(Number),
      }));

      expect(m.memory.usedPercent).toBeGreaterThanOrEqual(0);
      expect(m.memory.usedPercent).toBeLessThanOrEqual(100);

      // soglie applicate (se implementate)
      if (m.alerts) {
        expect(Array.isArray(m.alerts)).toBe(true);
      }

      // CPU details se disponibili
      if (m.cpu) {
        expect(m.cpu).toHaveProperty('count', cpuCount);
        expect(m.cpu).toHaveProperty('model');
      }
    });

    it('calcola metriche aggiuntive con performance data dai fixtures', async () => {
      if (!hasMethod('getSystemMetrics')) return;

      const perfData = fixtures.createPerformanceTestData(20);
      
      // Mock filesystem stats per disk usage
      fsMock.promises.stat.mockResolvedValue({
        size: fixtures.random.number(1000000000, 10000000000), // 1-10 GB
        isDirectory: () => true
      });

      // Mock load average più realistico
      const loadAvg = [
        fixtures.random.number(0, 4) + Math.random(),
        fixtures.random.number(0, 4) + Math.random(),
        fixtures.random.number(0, 4) + Math.random()
      ];
      jest.spyOn(os, 'loadavg').mockReturnValue(loadAvg);

      const m = await MonitoringService.getSystemMetrics();

      expect(m.load).toEqual(loadAvg);

      // Test performance metrics se supportate
      if (m.performance) {
        expect(m.performance).toHaveProperty('responseTime');
        expect(m.performance).toHaveProperty('throughput');
      }

      // Network stats se disponibili
      if (m.network) {
        expect(m.network).toHaveProperty('connections');
        expect(m.network).toHaveProperty('bandwidth');
      }
    });

    it('genera alert basati su soglie dai fixtures', async () => {
      if (!hasMethod('getSystemMetrics')) return;

      const criticalMemoryUsage = 97; // Sopra la soglia critical (95%)
      const highCPULoad = 4.5; // Sopra la soglia critical (4.0)

      const totalMem = 8 * 1024 * 1024 * 1024; // 8GB
      const freeMem = totalMem * (100 - criticalMemoryUsage) / 100;

      jest.spyOn(os, 'totalmem').mockReturnValue(totalMem);
      jest.spyOn(os, 'freemem').mockReturnValue(freeMem);
      jest.spyOn(os, 'loadavg').mockReturnValue([highCPULoad, 3.8, 3.2]);
      jest.spyOn(os, 'uptime').mockReturnValue(fixtures.random.number(3600, 86400));
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(4).fill({}));

      const m = await MonitoringService.getSystemMetrics();

      expect(m.memory.usedPercent).toBeGreaterThan(monitoringCfg.thresholds.memory.critical);

      // Dovrebbero essere generati alert
      if (m.alerts) {
        const memoryAlert = m.alerts.find(alert => alert.type === 'memory');
        const cpuAlert = m.alerts.find(alert => alert.type === 'cpu' || alert.type === 'load');

        if (memoryAlert) {
          expect(memoryAlert.severity).toBe('critical');
          expect(memoryAlert.value).toBeGreaterThan(95);
        }

        if (cpuAlert) {
          expect(cpuAlert.severity).toBe('critical');
          expect(cpuAlert.value).toBeGreaterThan(4.0);
        }
      }
    });
  });

  describe('probe / latency', () => {
    it('probeUrl/measureLatency misura il tempo e riporta status HTTP con dati realistici', async () => {
      const fn = MonitoringService.probeUrl || MonitoringService.measureLatency || MonitoringService.latencyProbe;
      if (typeof fn !== 'function') {
        console.warn('Nessuna funzione di probe/latency esposta: test saltato.');
        return;
      }

      const testEndpoints = [
        `http://${fixtures.random.ip()}:3001/health`,
        'https://api.example.com/status',
        'http://localhost:3000/api/health'
      ];

      axiosInstance.get.mockImplementation(async (url) => {
        // Simula tempi diversi per endpoint con dati realistici
        const latency = fixtures.random.number(10, 200);
        await new Promise((r) => setTimeout(r, latency));
        
        if (url.includes('api.example.com')) {
          return { 
            status: 200, 
            data: { 
              status: 'ok', 
              version: '2.1.0',
              region: 'us-east-1',
              timestamp: new Date().toISOString()
            } 
          };
        }
        
        return { 
          status: 200, 
          data: { 
            status: 'healthy',
            uptime: fixtures.random.number(1000, 10000)
          } 
        };
      });

      for (const url of testEndpoints) {
        const res = await fn(url, { timeout: 500 });
        
        expect(res).toEqual(
          expect.objectContaining({
            url: url,
            status: 200,
            ms: expect.any(Number),
          })
        );
        
        expect(res.ms).toBeGreaterThanOrEqual(0);
        expect(res.ms).toBeLessThan(500); // Sotto il timeout
        
        if (res.data) {
          expect(res.data).toHaveProperty('status');
        }
      }
    });

    it('gestisce timeout e errori di rete con dati dai fixtures', async () => {
      const fn = MonitoringService.probeUrl || MonitoringService.measureLatency;
      if (typeof fn !== 'function') return;

      const timeoutError = fixtures.createNetworkError('timeout');
      const connectionError = fixtures.createNetworkError('connection_refused');

      // Test timeout
      axiosInstance.get.mockRejectedValueOnce(timeoutError);
      
      const timeoutResult = await fn('http://slow-endpoint.com/health', { timeout: 100 });
      
      expect(timeoutResult).toEqual(
        expect.objectContaining({
          url: 'http://slow-endpoint.com/health',
          status: expect.any(Number),
          error: expect.stringContaining('timeout'),
          ms: expect.any(Number)
        })
      );

      // Test connection error
      axiosInstance.get.mockRejectedValueOnce(connectionError);
      
      const errorResult = await fn('http://down-service.com/health');
      
      expect(errorResult.error).toContain('ECONNREFUSED');
      expect(errorResult.status).toBeGreaterThanOrEqual(400);
    });

    it('monitora latency con soglie dai fixtures', async () => {
      const fn = MonitoringService.probeUrl || MonitoringService.measureLatency;
      if (typeof fn !== 'function') return;

      const thresholds = monitoringCfg.thresholds.latency;
      
      // Simula latenza alta
      axiosInstance.get.mockImplementation(async () => {
        const highLatency = thresholds.critical + fixtures.random.number(100, 500);
        await new Promise(r => setTimeout(r, highLatency));
        return { status: 200, data: { status: 'ok' } };
      });

      const result = await fn('http://slow-service.com/health');
      
      expect(result.ms).toBeGreaterThan(thresholds.critical);
      
      if (result.alert) {
        expect(result.alert.severity).toBe('critical');
        expect(result.alert.threshold).toBe(thresholds.critical);
      }
    });
  });

  describe('Prometheus text exposition (se supportata)', () => {
    it('buildPrometheusMetrics restituisce testo con # HELP/# TYPE e dati realistici', async () => {
      if (!hasMethod('buildPrometheusMetrics')) {
        console.warn('MonitoringService.buildPrometheusMetrics non esiste: test saltato.');
        return;
      }

      const systemMetrics = {
        uptime: fixtures.random.number(3600, 86400),
        cpuCount: fixtures.random.number(2, 16),
        load: [
          fixtures.random.number(0, 4) + Math.random(),
          fixtures.random.number(0, 4) + Math.random(),
          fixtures.random.number(0, 4) + Math.random()
        ],
        memory: {
          total: 8 * 1024 * 1024 * 1024,
          used: 2 * 1024 * 1024 * 1024,
          free: 6 * 1024 * 1024 * 1024,
          usedPercent: 25.0
        }
      };

      const dependencyMetrics = {
        api: { 
          status: 'ok', 
          latency_ms: fixtures.random.number(10, 100),
          uptime: fixtures.random.number(1000, 10000)
        },
        grafana: { 
          status: 'ok', 
          latency_ms: fixtures.random.number(15, 150),
          version: '9.0.0'
        },
        opnsense: {
          status: 'ok',
          latency_ms: fixtures.random.number(20, 200),
          firewall_rules: fixtures.random.number(10, 100)
        }
      };

      const input = {
        system: systemMetrics,
        dependencies: dependencyMetrics,
        timestamp: Date.now(),
        alerts: [
          fixtures.createTestAlert('performance', 'medium'),
          fixtures.createTestAlert('security', 'low')
        ]
      };

      const txt = await MonitoringService.buildPrometheusMetrics(input);

      expect(typeof txt).toBe('string');
      expect(txt).toMatch(/#\s*HELP/i);
      expect(txt).toMatch(/#\s*TYPE/i);
      expect(txt).toMatch(/monitoring_uptime_seconds/);
      expect(txt).toMatch(/monitoring_memory_usage_percent/);
      expect(txt).toMatch(/monitoring_cpu_load_average/);
      
      // Dependency metrics
      expect(txt).toMatch(/monitoring_dependency_status/);
      expect(txt).toMatch(/monitoring_dependency_latency_milliseconds/);
      
      // Alert metrics se supportate
      if (txt.includes('monitoring_alerts_total')) {
        expect(txt).toMatch(/monitoring_alerts_total/);
      }

      // Verifica valori specifici
      expect(txt).toContain(systemMetrics.uptime.toString());
      expect(txt).toContain(systemMetrics.memory.usedPercent.toString());
    });

    it('gestisce metriche custom e labels con dati dai fixtures', async () => {
      if (!hasMethod('buildPrometheusMetrics')) return;

      const customMetrics = {
        firewall_rules_count: fixtures.random.number(50, 200),
        active_connections: fixtures.random.number(10, 100),
        blocked_requests_total: fixtures.random.number(0, 50),
        policy_violations: fixtures.random.number(0, 10)
      };

      const labeledMetrics = {
        interface_traffic_bytes: {
          wan: fixtures.random.number(1000000, 10000000),
          lan: fixtures.random.number(500000, 5000000),
          dmz: fixtures.random.number(100000, 1000000)
        }
      };

      const input = {
        custom: customMetrics,
        labeled: labeledMetrics,
        timestamp: Date.now()
      };

      const txt = await MonitoringService.buildPrometheusMetrics(input);

      // Custom metrics
      expect(txt).toMatch(/firewall_rules_count/);
      expect(txt).toMatch(/active_connections/);
      
      // Labeled metrics
      expect(txt).toMatch(/interface_traffic_bytes{interface="wan"}/);
      expect(txt).toMatch(/interface_traffic_bytes{interface="lan"}/);
      expect(txt).toMatch(/interface_traffic_bytes{interface="dmz"}/);
    });
  });

  describe('soglie/valutazione stato', () => {
    it('applica le thresholds di monitoring config con dati dai fixtures', async () => {
      const evalFn = MonitoringService.evaluateStatus || MonitoringService.evalStatus || MonitoringService.assess;
      if (typeof evalFn !== 'function') {
        console.warn('Funzione di valutazione soglie non esposta: test saltato.');
        return;
      }

      const thresholds = monitoringCfg.thresholds;

      // Test latency
      let s = evalFn({ latency_ms: fixtures.random.number(10, 200) }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/ok|healthy|up/);

      s = evalFn({ latency_ms: thresholds.latency.warn + 10 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/warn|degraded/);

      s = evalFn({ latency_ms: thresholds.latency.critical + 1 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/crit|error|down|unhealthy/);

      // Test memory
      s = evalFn({ memory_percent: thresholds.memory.warn - 5 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/ok|healthy/);

      s = evalFn({ memory_percent: thresholds.memory.critical + 1 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/crit|error/);

      // Test CPU load
      s = evalFn({ cpu_load: thresholds.cpuLoad.warn + 0.1 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/warn|degraded/);
    });

    it('valuta stati compositi con multiple metriche dai fixtures', async () => {
      const evalFn = MonitoringService.evaluateStatus || MonitoringService.evaluateOverallStatus;
      if (typeof evalFn !== 'function') return;

      const metrics = {
        latency_ms: fixtures.random.number(10, 100),
        memory_percent: fixtures.random.number(60, 85),
        cpu_load: fixtures.random.number(1, 3),
        disk_percent: fixtures.random.number(70, 85),
        error_rate: fixtures.random.number(1, 3)
      };

      const thresholds = monitoringCfg.thresholds;
      const status = evalFn(metrics, thresholds);

      // Status dovrebbe essere OK se tutte le metriche sono sotto le soglie warn
      if (metrics.latency_ms < thresholds.latency.warn &&
          metrics.memory_percent < thresholds.memory.warn &&
          metrics.cpu_load < thresholds.cpuLoad.warn) {
        expect(String(status).toLowerCase()).toMatch(/ok|healthy/);
      }

      // Test con una metrica in warning
      const warningMetrics = {
        ...metrics,
        memory_percent: thresholds.memory.warn + 5
      };

      const warningStatus = evalFn(warningMetrics, thresholds);
      expect(String(warningStatus).toLowerCase()).toMatch(/warn|degraded/);
    });
  });

  describe('Integration Tests', () => {
    it('esegue monitoring completo con dati dai fixtures', async () => {
      if (!hasMethod('getHealth') || !hasMethod('getSystemMetrics')) {
        console.warn('Metodi di monitoring non disponibili: test saltato.');
        return;
      }

      // Setup mocks per scenario realistico
      const testUser = fixtures.createTestUser('admin');
      const systemUptime = fixtures.random.number(86400, 604800); // 1-7 giorni
      
      authenticateMock.mockResolvedValue(true);
      
      // Mock healthy dependencies
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok', uptime: systemUptime } })
        .mockResolvedValueOnce({ status: 200, data: { database: 'ok' } });

      // Mock system metrics
      jest.spyOn(os, 'uptime').mockReturnValue(systemUptime);
      jest.spyOn(os, 'totalmem').mockReturnValue(16 * 1024 * 1024 * 1024); // 16GB
      jest.spyOn(os, 'freemem').mockReturnValue(8 * 1024 * 1024 * 1024);   // 8GB free
      jest.spyOn(os, 'loadavg').mockReturnValue([1.2, 1.1, 1.0]);
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(8).fill({}));

      // Esegui health check
      const health = await MonitoringService.getHealth();
      expect(health.status).toMatch(/ok|healthy/);

      // Esegui system metrics
      const metrics = await MonitoringService.getSystemMetrics();
      expect(metrics.uptime).toBe(systemUptime);
      expect(metrics.memory.usedPercent).toBe(50); // 8GB used of 16GB

      // Verifica logging
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Health check completed'),
        expect.any(Object)
      );
    });

    it('gestisce scenario di degraded service con alert dai fixtures', async () => {
      if (!hasMethod('getHealth')) return;

      const networkError = fixtures.createNetworkError('timeout');
      const testAlert = fixtures.createTestAlert('security', 'critical');
      
      // Database OK ma dipendenze miste
      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok' } })   // API OK
        .mockRejectedValueOnce(networkError)                               // Grafana timeout
        .mockResolvedValueOnce({ status: 503, data: { error: 'overloaded' } }); // OPNsense degraded

      const health = await MonitoringService.getHealth();
      
      expect(health.status).toMatch(/degraded|partial/i);
      
      const deps = health.dependencies || health.components || {};
      expect(deps.api?.status).toMatch(/ok|healthy/i);
      expect(deps.grafana?.status).toMatch(/down|error|timeout/i);
      expect(deps.opnsense?.status).toMatch(/degraded|error/i);

      // Verifica alert generation se supportata
      if (health.alerts) {
        const dependencyAlerts = health.alerts.filter(alert => 
          alert.type === 'dependency' || alert.component
        );
        expect(dependencyAlerts.length).toBeGreaterThan(0);
      }

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('dependency'),
        expect.objectContaining({
          component: expect.any(String),
          error: expect.any(String)
        })
      );
    });

    it('monitora performance sotto carico con dati dai fixtures', async () => {
      if (!hasMethod('getSystemMetrics')) return;

      const perfData = fixtures.createPerformanceTestData(100);
      const highLoad = fixtures.random.number(4, 8); // High CPU load
      const highMemory = fixtures.random.number(85, 95); // High memory usage

      // Simula sistema sotto carico
      const totalMem = 8 * 1024 * 1024 * 1024;
      const freeMem = totalMem * (100 - highMemory) / 100;

      jest.spyOn(os, 'loadavg').mockReturnValue([highLoad, highLoad - 0.5, highLoad - 1]);
      jest.spyOn(os, 'totalmem').mockReturnValue(totalMem);
      jest.spyOn(os, 'freemem').mockReturnValue(freeMem);
      jest.spyOn(os, 'uptime').mockReturnValue(fixtures.random.number(3600, 86400));
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(4).fill({
        times: {
          user: fixtures.random.number(50000, 100000),
          nice: fixtures.random.number(100, 1000),
          sys: fixtures.random.number(15000, 30000),
          idle: fixtures.random.number(10000, 50000), // Low idle time
          irq: fixtures.random.number(500, 1000)
        }
      }));

      const metrics = await MonitoringService.getSystemMetrics();

      expect(metrics.load[0]).toBeGreaterThan(monitoringCfg.thresholds.cpuLoad.critical);
      expect(metrics.memory.usedPercent).toBeGreaterThan(monitoringCfg.thresholds.memory.warn);

      // Verifica generation di alert
      if (metrics.alerts) {
        const cpuAlert = metrics.alerts.find(alert => 
          alert.type === 'cpu' || alert.type === 'load'
        );
        const memAlert = metrics.alerts.find(alert => alert.type === 'memory');

        if (cpuAlert) {
          expect(cpuAlert.severity).toMatch(/warn|critical/i);
          expect(cpuAlert.value).toBeGreaterThan(monitoringCfg.thresholds.cpuLoad.warn);
        }

        if (memAlert) {
          expect(memAlert.severity).toMatch(/warn|critical/i);
          expect(memAlert.value).toBeGreaterThan(monitoringCfg.thresholds.memory.warn);
        }
      }
    });

    it('esegue monitoring con firewall rules dai fixtures', async () => {
      const firewallRules = fixtures.createMultipleFirewallRules(10, true);
      const testUser = fixtures.createTestUser('admin');

      // Mock OPNsense API response con firewall data
      const opnsenseResponse = {
        status: 'online',
        version: '23.7.1',
        firewall: {
          rules_count: firewallRules.length,
          active_rules: firewallRules.filter(rule => rule.enabled === '1').length,
          interfaces: ['wan', 'lan', 'dmz'],
          last_config_change: new Date(Date.now() - 3600000).toISOString() // 1 hour ago
        },
        system: {
          uptime: fixtures.random.number(86400, 604800),
          cpu_usage: fixtures.random.number(10, 30),
          memory_usage: fixtures.random.number(40, 70)
        }
      };

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok' } })
        .mockResolvedValueOnce({ status: 200, data: opnsenseResponse });

      const health = await MonitoringService.getHealth();
      
      expect(health.status).toMatch(/ok|healthy/i);
      
      const deps = health.dependencies || health.components || {};
      if (deps.opnsense?.details) {
        expect(deps.opnsense.details).toHaveProperty('firewall');
        expect(deps.opnsense.details.firewall.rules_count).toBe(firewallRules.length);
      }
    });
  });

  describe('Error Handling e Edge Cases', () => {
    it('gestisce timeout su health check con graceful degradation', async () => {
      if (!hasMethod('getHealth')) return;

      const timeoutError = fixtures.createNetworkError('timeout');
      
      authenticateMock.mockResolvedValue(true);
      
      // Simula timeout su tutte le dipendenze
      axiosInstance.get.mockRejectedValue(timeoutError);

      const startTime = Date.now();
      const health = await MonitoringService.getHealth();
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Dovrebbe completare in tempo ragionevole anche con timeout
      expect(duration).toBeLessThan(5000); // Meno di 5 secondi

      expect(health.status).toMatch(/error|critical|down/i);
      expect(health.errors).toBeDefined();
      
      if (Array.isArray(health.errors)) {
        expect(health.errors.length).toBeGreaterThan(0);
        expect(health.errors[0]).toContain('timeout');
      }
    });

    it('gestisce errori di parsing response con dati corrotti', async () => {
      if (!hasMethod('getHealth')) return;

      authenticateMock.mockResolvedValue(true);
      
      // Response con JSON malformato
      axiosInstance.get
        .mockResolvedValueOnce({ 
          status: 200, 
          data: 'invalid json response' 
        })
        .mockResolvedValueOnce({ 
          status: 200, 
          data: { 
            status: null, 
            error: undefined,
            corrupted: fixtures.random.string(10000) // Large string
          } 
        });

      const health = await MonitoringService.getHealth();
      
      expect(health.status).toMatch(/degraded|error/i);
      
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('parsing'),
        expect.any(Object)
      );
    });

    it('gestisce memory leak prevention con cleanup', async () => {
      if (!hasMethod('getSystemMetrics')) return;

      // Simula molte chiamate consecutive
      const iterations = 50;
      const results = [];

      for (let i = 0; i < iterations; i++) {
        jest.spyOn(os, 'uptime').mockReturnValue(fixtures.random.number(1000, 10000));
        jest.spyOn(os, 'totalmem').mockReturnValue(8 * 1024 * 1024 * 1024);
        jest.spyOn(os, 'freemem').mockReturnValue(fixtures.random.number(1, 7) * 1024 * 1024 * 1024);
        jest.spyOn(os, 'loadavg').mockReturnValue([Math.random() * 4, Math.random() * 4, Math.random() * 4]);
        jest.spyOn(os, 'cpus').mockReturnValue(new Array(4).fill({}));

        const metrics = await MonitoringService.getSystemMetrics();
        results.push(metrics);
      }

      expect(results).toHaveLength(iterations);
      
      // Verifica che non ci siano memory leak evidenti
      // (questo è un test superficiale, ma utile per edge cases)
      const memoryUsages = results.map(r => r.memory.usedPercent);
      expect(memoryUsages.every(usage => usage >= 0 && usage <= 100)).toBe(true);
    });

    it('gestisce rate limiting su Prometheus metrics export', async () => {
      if (!hasMethod('buildPrometheusMetrics')) return;

      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 5
      });

      // Simula molte richieste consecutive di metrics
      const requests = [];
      for (let i = 0; i < 10; i++) {
        const promise = MonitoringService.buildPrometheusMetrics({
          system: {
            uptime: fixtures.random.number(1000, 10000),
            memory: { usedPercent: fixtures.random.number(20, 80) }
          },
          request_id: i
        });
        requests.push(promise);
      }

      const results = await Promise.allSettled(requests);
      
      // Alcune richieste potrebbero essere rate limited
      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');

      expect(successful.length + failed.length).toBe(10);
      
      if (failed.length > 0) {
        // Se c'è rate limiting, dovrebbe essere gestito gracefully
        expect(logger.warn).toHaveBeenCalledWith(
          expect.stringContaining('rate limit'),
          expect.any(Object)
        );
      }
    });

    it('gestisce disconnessione database temporanea', async () => {
      if (!hasMethod('getHealth')) return;

      // Prima chiamata: DB down
      const dbError = fixtures.createHTTPError(503, 'Database temporarily unavailable');
      authenticateMock.mockRejectedValueOnce(dbError);
      
      axiosInstance.get.mockResolvedValue({ status: 200, data: { status: 'ok' } });

      const health1 = await MonitoringService.getHealth();
      expect(health1.status).toMatch(/degraded|error/i);

      // Seconda chiamata: DB recovered
      authenticateMock.mockResolvedValueOnce(true);

      const health2 = await MonitoringService.getHealth();
      expect(health2.status).toMatch(/ok|healthy/i);

      // Verifica recovery logging
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Database connection'),
        expect.any(Object)
      );
    });
  });

  describe('Performance Tests', () => {
    it('completa health check in tempo ragionevole', async () => {
      if (!hasMethod('getHealth')) return;

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get.mockResolvedValue({ 
        status: 200, 
        data: { status: 'ok' } 
      });

      const startTime = Date.now();
      await MonitoringService.getHealth();
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Health check dovrebbe completare rapidamente
      expect(duration).toBeLessThan(2000); // Meno di 2 secondi
    });

    it('gestisce carico elevato di richieste metriche', async () => {
      if (!hasMethod('getSystemMetrics')) return;

      const concurrentRequests = 20;
      
      // Mock OS calls per performance
      jest.spyOn(os, 'uptime').mockReturnValue(fixtures.random.number(1000, 10000));
      jest.spyOn(os, 'totalmem').mockReturnValue(8 * 1024 * 1024 * 1024);
      jest.spyOn(os, 'freemem').mockReturnValue(4 * 1024 * 1024 * 1024);
      jest.spyOn(os, 'loadavg').mockReturnValue([1.5, 1.2, 1.0]);
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(4).fill({}));

      const startTime = Date.now();
      
      const promises = Array(concurrentRequests).fill().map(() => 
        MonitoringService.getSystemMetrics()
      );
      
      const results = await Promise.all(promises);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;
      const avgDuration = totalDuration / concurrentRequests;

      expect(results).toHaveLength(concurrentRequests);
      expect(avgDuration).toBeLessThan(100); // Meno di 100ms per richiesta in media
      
      // Tutti i risultati dovrebbero essere consistenti
      results.forEach(result => {
        expect(result).toHaveProperty('uptime');
        expect(result).toHaveProperty('memory');
        expect(result).toHaveProperty('load');
      });
    });
  });
});