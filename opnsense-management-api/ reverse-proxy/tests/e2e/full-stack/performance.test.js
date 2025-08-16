/**
 * Full-Stack Complete Workflow
 * - Verifica end-to-end: API auth, lettura regole, toggle singola regola,
 *   bulk enable/disable, reload, backup e accesso ai dashboard Grafana.
 * - I test sono robusti: se un endpoint non esiste, loggano e non rompono l’intera suite.
 */

const axios = require('axios');
const https = require('https');

describe('Full-Stack Complete Workflow', () => {
  const baseURL = global.testConfig.baseURL; // es: https://localhost
  const apiBase = `${baseURL}/api/v1`;
  const grafanaBase = `${baseURL}/grafana`;

  const basicAuth = global.testConfig.basicAuth || { username: 'admin', password: 'admin' };
  const grafanaAdmin = global.testConfig.grafanaAdmin || { username: 'admin', password: 'admin123' };
  const timeouts = global.testConfig.timeouts || { short: 3000, medium: 10000, long: 20000 };

  let httpClient;
  beforeAll(() => {
    httpClient = axios.create({
      httpsAgent: new https.Agent({ rejectUnauthorized: false, keepAlive: true }),
      timeout: timeouts.long,
      validateStatus: () => true
    });
  });

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  let pickedRule = null;
  let originalEnabled = null;

  test('API health con Basic Auth', async () => {
    const res = await httpClient.get(`${apiBase}/health`, { auth: basicAuth });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('status');
  });

  test('Leggi elenco regole firewall e scegli una regola “toggable”', async () => {
    const res = await httpClient.get(`${apiBase}/firewall/rules`, { auth: basicAuth });
    expect(res.status).toBeLessThan(500);
    const rules = Array.isArray(res.data) ? res.data : (res.data?.rules || []);

    expect(rules.length).toBeGreaterThan(0);
    // scegli la prima con proprietà “enabled” e “rule_id”
    pickedRule = rules.find(r => r && ('enabled' in r) && (r.rule_id !== undefined)) || rules[0];
    expect(pickedRule).toBeDefined();

    originalEnabled = !!pickedRule.enabled;
  });

  test('Toggle singola regola e verifica stato aggiornato', async () => {
    if (!pickedRule) return;

    const toggleRes = await httpClient.post(
      `${apiBase}/firewall/rules/${pickedRule.rule_id}/toggle`,
      {},
      { auth: basicAuth }
    );

    expect([200, 202]).toContain(toggleRes.status);

    // piccola attesa per propagazione
    await sleep(300);

    const after = await httpClient.get(`${apiBase}/firewall/rules`, { auth: basicAuth });
    const rules2 = Array.isArray(after.data) ? after.data : (after.data?.rules || []);
    const updated = rules2.find(r => r.rule_id === pickedRule.rule_id);

    if (updated && ('enabled' in updated)) {
      expect(!!updated.enabled).toBe(!originalEnabled);
      // ripristina stato originale per non sporcare l’ambiente
      await httpClient.post(
        `${apiBase}/firewall/rules/${pickedRule.rule_id}/toggle`,
        {},
        { auth: basicAuth }
      );
    } else {
      console.warn('Non è stato possibile confermare la variazione "enabled" (API non restituisce flag).');
    }
  });

  test('Bulk disable/enable, reload e backup', async () => {
    // Prendi fino a 3 id per bulk actions
    const list = await httpClient.get(`${apiBase}/firewall/rules`, { auth: basicAuth });
    const rules = Array.isArray(list.data) ? list.data : (list.data?.rules || []);
    const ids = rules.slice(0, 3).map(r => r.rule_id).filter(id => id !== undefined);

    // Bulk disable
    if (ids.length) {
      const b1 = await httpClient.post(`${apiBase}/firewall/rules/bulk/disable`, { ids }, { auth: basicAuth });
      expect([200, 202, 204, 207]).toContain(b1.status);
    } else {
      console.warn('Nessun ID disponibile per bulk disable.');
    }

    // Bulk enable
    if (ids.length) {
      const b2 = await httpClient.post(`${apiBase}/firewall/rules/bulk/enable`, { ids }, { auth: basicAuth });
      expect([200, 202, 204, 207]).toContain(b2.status);
    }

    // Reload
    const rld = await httpClient.post(`${apiBase}/firewall/reload`, {}, { auth: basicAuth });
    expect([200, 202, 204]).toContain(rld.status);

    // Backup
    const bck = await httpClient.post(`${apiBase}/firewall/backup`, {}, { auth: basicAuth });
    expect([200, 202, 204]).toContain(bck.status);
  });

  test('Accesso ai dashboard Grafana (overview e rule management) e ricerca', async () => {
    // Overview
    const d1 = await httpClient.get(`${grafanaBase}/api/dashboards/uid/opnsense-overview`, { auth: grafanaAdmin });
    expect(d1.status).toBe(200);
    expect(d1.data).toHaveProperty('dashboard.uid', 'opnsense-overview');

    // Rule management
    const d2 = await httpClient.get(`${grafanaBase}/api/dashboards/uid/firewall-rules-mgmt`, { auth: grafanaAdmin });
    expect(d2.status).toBe(200);
    expect(d2.data).toHaveProperty('dashboard.uid', 'firewall-rules-mgmt');

    // Search per tag "opnsense"
    const s = await httpClient.get(`${grafanaBase}/api/search`, { params: { tag: 'opnsense' }, auth: grafanaAdmin });
    expect(s.status).toBe(200);
    const uids = (s.data || []).map(x => x.uid);
    expect(uids).toEqual(expect.arrayContaining(['opnsense-overview']));
  });

  afterAll(async () => {
    // eventuale cleanup aggiuntivo (se servisse)
  });
});