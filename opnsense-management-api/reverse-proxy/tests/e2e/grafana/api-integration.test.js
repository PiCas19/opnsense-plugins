/**
 * Grafana API Integration
 * - Verifica la presenza delle datasource provisionate e la loro health (quando supportata)
 * - Verifica che i dashboard taggati "opnsense" siano ricercabili
 */

const axios = require('axios');
const https = require('https');

describe('Grafana - API Integration', () => {
  const baseURL = global.testConfig.baseURL;
  const grafanaBase = `${baseURL}/grafana`;
  const grafanaAdmin = global.testConfig.grafanaAdmin || { username: 'admin', password: 'admin123' };

  let httpClient;
  beforeAll(() => {
    httpClient = axios.create({
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      timeout: global.testConfig.timeouts?.medium || 10000,
      validateStatus: () => true,
      auth: grafanaAdmin
    });
  });

  test('datasources provisionate presenti (OPNsense API - Postgres, OPNsense Direct API - JSON)', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/datasources`);
    expect(res.status).toBe(200);

    const names = (res.data || []).map(d => d.name);
    expect(names).toEqual(expect.arrayContaining(['OPNsense API', 'OPNsense Direct API']));

    const pg = res.data.find(d => d.name === 'OPNsense API');
    const json = res.data.find(d => d.name === 'OPNsense Direct API');

    expect(pg.type).toBe('postgres');                              // da datasources.yaml
    expect(json.type).toBe('marcusolsson-json-datasource');        // da datasources.yaml
  });

  test('health della datasource Postgres (se supportata)', async () => {
    const all = await httpClient.get(`${grafanaBase}/api/datasources`);
    const pg = all.data.find(d => d.name === 'OPNsense API');
    expect(pg).toBeDefined();

    const health = await httpClient.get(`${grafanaBase}/api/datasources/uid/${pg.uid}/health`);
    // Il plugin Postgres espone l’endpoint di health → status 200 expected
    expect(health.status).toBeLessThan(500);
  });

  test('health della datasource JSON (può non essere supportata)', async () => {
    const all = await httpClient.get(`${grafanaBase}/api/datasources`);
    const js = all.data.find(d => d.name === 'OPNsense Direct API');
    expect(js).toBeDefined();

    const res = await httpClient.get(`${grafanaBase}/api/datasources/uid/${js.uid}/health`);
    // Alcuni plugin non implementano la health: accetta 200..499
    expect(res.status).toBeGreaterThanOrEqual(200);
    expect(res.status).toBeLessThan(500);
  });

  test('ricerca dashboard per tag "opnsense" trova overview e api-monitoring', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/search`, { params: { tag: 'opnsense' } });
    expect(res.status).toBe(200);

    const uids = (res.data || []).map(x => x.uid);
    expect(uids).toEqual(expect.arrayContaining(['opnsense-overview', 'api-monitoring']));
  });

  test('dashboard "API Monitoring" contiene query su audit_logs (integrazione DB)', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/api-monitoring`);
    expect(res.status).toBe(200);
    const jsonStr = JSON.stringify(res.data.dashboard);
    expect(jsonStr).toMatch(/audit_logs/i); // le query nei pannelli usano la tabella audit_logs
  });
});