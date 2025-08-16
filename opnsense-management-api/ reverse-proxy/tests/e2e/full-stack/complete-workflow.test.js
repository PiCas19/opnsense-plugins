/**
 * Full-Stack Performance Tests (Nginx + API + Grafana)
 * - Misura p95 latency per /api e /grafana
 * - Verifica concorrenza (HTTP/2) con richieste parallele
 */

const axios = require('axios');
const https = require('https');

describe('Full-Stack Performance', () => {
  const baseURL = global.testConfig.baseURL; // es: https://localhost
  const grafanaBase = `${baseURL}/grafana`;
  const apiBase = `${baseURL}/api/v1`;

  const basicAuth = global.testConfig.basicAuth || { username: 'admin', password: 'admin' };
  const timeouts = global.testConfig.timeouts || { short: 3000, medium: 10000, long: 20000 };
  const PERF = Object.assign({
    rounds: 50,            // numero richieste per misurare p95
    p95_ms: 400,           // soglia p95
    h2_concurrency: 16,    // richieste parallele
    static_rounds: 20      // richieste per asset statico
  }, global.testConfig.performance || {});

  let httpClient;
  beforeAll(() => {
    httpClient = axios.create({
      httpsAgent: new https.Agent({ rejectUnauthorized: false, keepAlive: true }),
      timeout: timeouts.medium,
      validateStatus: () => true
    });
  });

  const measure = async (fn, n) => {
    const times = [];
    for (let i = 0; i < n; i++) {
      const t0 = Date.now();
      const res = await fn();
      const dt = Date.now() - t0;
      times.push(dt);
      expect(res.status).toBeLessThan(500); // niente 5xx
    }
    times.sort((a, b) => a - b);
    const p95 = times[Math.floor(0.95 * (times.length - 1))];
    return { times, p95 };
  };

  test(`API /health p95 < ${PERF.p95_ms}ms su ${PERF.rounds} richieste`, async () => {
    const { p95 } = await measure(
      () => httpClient.get(`${apiBase}/health`, { auth: basicAuth }),
      PERF.rounds
    );
    // p95 ragionevole (in CI o locale)
    expect(p95).toBeLessThanOrEqual(PERF.p95_ms);
  }, timeouts.long * 2);

  test(`Grafana /api/health p95 < ${PERF.p95_ms}ms su ${PERF.rounds} richieste`, async () => {
    const { p95 } = await measure(
      () => httpClient.get(`${grafanaBase}/api/health`),
      PERF.rounds
    );
    expect(p95).toBeLessThanOrEqual(PERF.p95_ms);
  }, timeouts.long * 2);

  test(`Concorrenza: ${PERF.h2_concurrency} richieste parallele (API + Grafana) senza errori`, async () => {
    const batch = [];
    for (let i = 0; i < PERF.h2_concurrency; i++) {
      // alterna API e Grafana
      const url = i % 2 === 0 ? `${apiBase}/health` : `${grafanaBase}/api/health`;
      batch.push(httpClient.get(url, i % 2 === 0 ? { auth: basicAuth } : {}));
    }
    const res = await Promise.all(batch);
    res.forEach(r => expect(r.status).toBeLessThan(500));
  }, timeouts.long);

  test(`Asset statico: /grafana/public/img/grafana_icon.svg p95 < ${PERF.p95_ms}ms`, async () => {
    const { p95 } = await measure(
      () => httpClient.get(`${grafanaBase}/public/img/grafana_icon.svg`),
      PERF.static_rounds
    );
    expect(p95).toBeLessThanOrEqual(PERF.p95_ms);
  }, timeouts.long);
});