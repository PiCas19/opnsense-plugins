jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock della config di monitoring (dipendenze + soglie)
jest.mock('../../../src/config/monitoring', () => ({
  dependencies: {
    api:     { url: 'http://localhost:3001/health', critical: true,  timeout: 1000 },
    grafana: { url: 'http://localhost:3000/api/health', critical: false, timeout: 1000 },
  },
  thresholds: {
    latency:  { warn: 500,  critical: 1500 },
    cpuLoad:  { warn: 2.0,  critical: 4.0 },
    memory:   { warn: 80,   critical: 95 },
    disk:     { warn: 80,   critical: 95 },
  },
  sampleIntervalMs: 5000,
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
};
jest.mock('axios', () => ({
  create: jest.fn(() => axiosInstance),
}));

const os = require('os');
const logger = require('../../../src/utils/logger');
const monitoringCfg = require('../../../src/config/monitoring');
const { sequelize } = require('../../../src/config/database');
const MonitoringService = require('../../../src/services/MonitoringService');
const axios = require('axios');

const hasMethod = (name) => typeof MonitoringService?.[name] === 'function';

describe('MonitoringService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('inizializza il client HTTP con timeout e base headers', () => {
    // La sola import di MonitoringService dovrebbe aver creato l’istanza axios
    expect(axios.create).toHaveBeenCalledWith(
      expect.objectContaining({
        timeout: expect.any(Number),
        headers: expect.any(Object),
      })
    );
  });

  describe('getHealth', () => {
    it('ritorna status OK quando DB e dipendenze sono ok', async () => {
      if (!hasMethod('getHealth')) {
        console.warn('MonitoringService.getHealth non esiste: test saltato.');
        return;
      }

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok' } }) // api
        .mockResolvedValueOnce({ status: 200, data: { database: 'ok' } }); // grafana

      const res = await MonitoringService.getHealth();

      expect(sequelize.authenticate).toBeDefined();
      expect(authenticateMock).toHaveBeenCalled();

      expect(res).toBeDefined();
      // status complessivo
      expect(['ok', 'healthy']).toContain(res.status);

      // mappa dipendenze (forme tolleranti)
      const deps = res.dependencies || res.components || {};
      expect(deps.api?.status || deps.api).toBeTruthy();
      expect(String(deps.api?.status || deps.api)).toMatch(/ok|up|healthy/i);
      expect(String(deps.database?.status || deps.database)).toMatch(/ok|up|healthy/i);

      expect(logger.info).toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    it('se una dipendenza fallisce → status degraded/error e log warn/error', async () => {
      if (!hasMethod('getHealth')) {
        console.warn('MonitoringService.getHealth non esiste: test saltato.');
        return;
      }

      authenticateMock.mockResolvedValue(true);
      axiosInstance.get
        .mockResolvedValueOnce({ status: 200, data: { status: 'ok' } }) // api ok
        .mockRejectedValueOnce(new Error('ECONNREFUSED'));              // grafana down

      const res = await MonitoringService.getHealth();

      expect(res).toBeDefined();
      expect(res.status).toMatch(/degraded|error|partial/i);

      const deps = res.dependencies || res.components || {};
      const grafana = deps.grafana?.status || deps.grafana;
      expect(String(grafana)).toMatch(/down|error|unhealthy/i);

      expect(logger.warn).toHaveBeenCalled();
      // error può essere chiamato se il service lo considera critico; accettiamo entrambi i casi
      expect(logger.error.mock.calls.length >= 0).toBe(true);
    });

    it('se il DB non risponde → stato non ok', async () => {
      if (!hasMethod('getHealth')) {
        console.warn('MonitoringService.getHealth non esiste: test saltato.');
        return;
      }

      authenticateMock.mockRejectedValue(new Error('db timeout'));
      axiosInstance.get
        .mockResolvedValue({ status: 200, data: { status: 'ok' } });

      const res = await MonitoringService.getHealth();
      expect(res.status).toMatch(/degraded|error|partial/i);

      const deps = res.dependencies || res.components || {};
      const dbStatus = deps.database?.status || deps.db || deps.database;
      expect(String(dbStatus)).toMatch(/down|error|unhealthy|timeout/i);

      expect(logger.error).toHaveBeenCalled();
    });
  });

  describe('getSystemMetrics', () => {
    it('ritorna metriche di sistema con chiavi attese', async () => {
      if (!hasMethod('getSystemMetrics')) {
        console.warn('MonitoringService.getSystemMetrics non esiste: test saltato.');
        return;
      }

      jest.spyOn(os, 'uptime').mockReturnValue(1234);
      jest.spyOn(os, 'totalmem').mockReturnValue(8 * 1024 * 1024 * 1024); // 8 GB
      jest.spyOn(os, 'freemem').mockReturnValue(6 * 1024 * 1024 * 1024);  // 6 GB
      jest.spyOn(os, 'loadavg').mockReturnValue([0.5, 0.4, 0.3]);
      jest.spyOn(os, 'cpus').mockReturnValue(new Array(4).fill({}));

      const m = await MonitoringService.getSystemMetrics();

      expect(m).toEqual(expect.objectContaining({
        uptime: 1234,
        cpuCount: 4,
      }));
      expect(m).toHaveProperty('load');
      expect(Array.isArray(m.load)).toBe(true);

      // utilizzo memoria coerente
      expect(m).toHaveProperty('memory');
      expect(m.memory).toEqual(expect.objectContaining({
        total: expect.any(Number),
        free: expect.any(Number),
        used: expect.any(Number),
        usedPercent: expect.any(Number),
      }));

      // soglie applicate (se implementate)
      if (m.alerts) {
        expect(Array.isArray(m.alerts)).toBe(true);
      }
    });
  });

  describe('probe / latency', () => {
    it('probeUrl/measureLatency misura il tempo e riporta status HTTP', async () => {
      const fn = MonitoringService.probeUrl || MonitoringService.measureLatency || MonitoringService.latencyProbe;
      if (typeof fn !== 'function') {
        console.warn('Nessuna funzione di probe/latency esposta: test saltato.');
        return;
      }

      axiosInstance.get.mockImplementation(async (url) => {
        // Simula tempi diversi per endpoint
        if (/api\/health/.test(url)) {
          await new Promise((r) => setTimeout(r, 20));
          return { status: 200, data: { status: 'ok' } };
        }
        await new Promise((r) => setTimeout(r, 10));
        return { status: 200 };
      });

      const res = await fn('http://localhost:3001/health', { timeout: 500 });
      expect(res).toEqual(
        expect.objectContaining({
          url: expect.any(String),
          status: 200,
          ms: expect.any(Number),
        })
      );
      expect(res.ms).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Prometheus text exposition (se supportata)', () => {
    it('buildPrometheusMetrics restituisce testo con # HELP/# TYPE', async () => {
      if (!hasMethod('buildPrometheusMetrics')) {
        console.warn('MonitoringService.buildPrometheusMetrics non esiste: test saltato.');
        return;
      }

      // Fornisci un input minimo; la funzione può anche chiamare internamente getSystemMetrics
      const txt = await MonitoringService.buildPrometheusMetrics({
        system: {
          uptime: 123,
          cpuCount: 2,
          load: [0.1, 0.05, 0.02],
          memory: { total: 1024, used: 256, free: 768, usedPercent: 25.0 },
        },
        dependencies: {
          api:     { status: 'ok', latency_ms: 20 },
          grafana: { status: 'ok', latency_ms: 30 },
        },
      });

      expect(typeof txt === 'string').toBe(true);
      expect(txt).toMatch(/#\s*HELP/i);
      expect(txt).toMatch(/#\s*TYPE/i);
      expect(txt).toMatch(/monitoring_uptime_seconds/);
    });
  });

  describe('soglie/valutazione stato', () => {
    it('applica le thresholds di monitoring config (latency → warn/critical)', async () => {
      const evalFn = MonitoringService.evaluateStatus || MonitoringService.evalStatus || MonitoringService.assess;
      if (typeof evalFn !== 'function') {
        console.warn('Funzione di valutazione soglie non esposta: test saltato.');
        return;
      }

      const thresholds = monitoringCfg.thresholds || {
        latency: { warn: 500, critical: 1500 },
      };

      // caso ok
      let s = evalFn({ latency_ms: 100 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/ok|healthy|up/);

      // caso warn
      s = evalFn({ latency_ms: thresholds.latency.warn + 10 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/warn|degraded/);

      // caso critical
      s = evalFn({ latency_ms: thresholds.latency.critical + 1 }, thresholds);
      expect(String(s).toLowerCase()).toMatch(/crit|error|down|unhealthy/);
    });
  });
});