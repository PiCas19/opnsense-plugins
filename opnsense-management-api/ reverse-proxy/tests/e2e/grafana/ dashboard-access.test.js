/**
 * Grafana Dashboard Access (via reverse proxy)
 * - Verifica health, accesso via subpath /grafana/, headers di sicurezza e presenza dei dashboard pre-provisionati
 */

const axios = require('axios');
const https = require('https');

describe('Grafana - Dashboard Access (through Nginx)', () => {
  const baseURL = global.testConfig.baseURL;                 // es: https://localhost
  const grafanaBase = `${baseURL}/grafana`;                  // serve-from-sub-path
  const grafanaAdmin = global.testConfig.grafanaAdmin || {   // fallback -> compose defaults
    username: 'admin',
    password: 'admin123'
  };

  let httpClient;
  beforeAll(() => {
    httpClient = axios.create({
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      timeout: global.testConfig.timeouts?.medium || 10000,
      validateStatus: () => true
    });
  });

  test('root (/) dovrebbe reindirizzare a /grafana/', async () => {
    const res = await httpClient.get(`${baseURL}/`, { maxRedirects: 0 });
    expect([301, 302]).toContain(res.status);
    expect(res.headers.location).toMatch(/\/grafana\/?$/);
  });

  test('GET /grafana/api/health deve rispondere 200 e includere lo stato database', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/health`);
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('database'); // es. "ok"
    expect(res.data).toHaveProperty('version');  // versione grafana
  });

  test('headers di sicurezza presenti sulle risposte via proxy', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/health`);
    expect(res.headers['x-frame-options']).toBeDefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-xss-protection']).toBeDefined();
  });

  test('serving da subpath: asset pubblico disponibile', async () => {
    const res = await httpClient.get(`${grafanaBase}/public/img/grafana_icon.svg`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/image\/svg\+xml/);
  });

  test('dashboard "OPNsense Overview" accessibile per UID', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/opnsense-overview`, {
      auth: grafanaAdmin
    });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('dashboard.uid', 'opnsense-overview');
    expect(Array.isArray(res.data.dashboard.panels)).toBe(true);
  });

  test('dashboard "API Monitoring" accessibile per UID', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/api-monitoring`, {
      auth: grafanaAdmin
    });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('dashboard.uid', 'api-monitoring');
  });
});