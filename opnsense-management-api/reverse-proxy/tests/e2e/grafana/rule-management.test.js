/**
 * Grafana - Firewall Rule Management Dashboard
 * - Convalida struttura del dashboard, link e azioni (toggle/ bulk / reload / backup)
 */

const axios = require('axios');
const https = require('https');

describe('Grafana - Firewall Rule Management dashboard', () => {
  const baseURL = global.testConfig.baseURL;
  const grafanaBase = `${baseURL}/grafana`;
  const grafanaAdmin = global.testConfig.grafanaAdmin || { username: 'admin', password: 'admin123' };

  let httpClient;
  beforeAll(() => {
    httpClient = axios.create({
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      timeout: global.testConfig.timeouts?.long || 20000,
      validateStatus: () => true,
      auth: grafanaAdmin
    });
  });

  test('dashboard "firewall-rules-mgmt" caricato correttamente', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/firewall-rules-mgmt`);
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('dashboard.uid', 'firewall-rules-mgmt');
  });

  test('tabella "Regole Firewall" espone override con pulsante toggle verso /api/v1/firewall/rules/${rule_id}/toggle', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/firewall-rules-mgmt`);
    const dash = res.data.dashboard;

    const table = (dash.panels || []).find(p => p.title && /Regole Firewall/i.test(p.title));
    expect(table).toBeDefined();

    const overrides = (table.fieldConfig && table.fieldConfig.overrides) || [];
    const enabledOverride = overrides.find(o => o.matcher?.options === 'enabled');
    expect(enabledOverride).toBeDefined();

    const btnCfg = enabledOverride.properties?.find(p => p.id === 'custom.cellOptions')?.value;
    expect(btnCfg?.type).toBe('button');
    expect(btnCfg?.onClick?.url).toMatch(/\/api\/v1\/firewall\/rules\/\$\{__data\.fields\.rule_id\}\/toggle/);
    expect(btnCfg?.onClick?.method).toBe('POST');
  });

  test('pannello "Controlli Rapidi" contiene azioni bulk enable/disable, reload e backup', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/firewall-rules-mgmt`);
    const dash = res.data.dashboard;

    const textPanel = (dash.panels || []).find(p => p.title && /Controlli Rapidi|Azioni Rapide/i.test(p.title));
    expect(textPanel).toBeDefined();

    const content = textPanel.options?.content || '';
    expect(content).toMatch(/\/api\/v1\/firewall\/rules\/bulk\/enable/);
    expect(content).toMatch(/\/api\/v1\/firewall\/rules\/bulk\/disable/);
    expect(content).toMatch(/\/api\/v1\/firewall\/reload/);
    expect(content).toMatch(/\/api\/v1\/firewall\/backup/);
  });

  test('dall\'overview esiste un link a /d/firewall-rules-mgmt', async () => {
    const res = await httpClient.get(`${grafanaBase}/api/dashboards/uid/opnsense-overview`);
    expect(res.status).toBe(200);
    const links = res.data.dashboard.links || [];
    expect(links.some(l => l.url === '/d/firewall-rules-mgmt')).toBe(true);
  });
});