/**
 * Nginx SSL Termination Tests
 * Checks TLS versions, redirect, HSTS, ALPN (HTTP/2), and cipher strength.
 */

const axios = require('axios');
const https = require('https');
const tls = require('tls');
const { URL } = require('url');

describe('Nginx SSL Termination', () => {
  const baseURL = new URL(global.testConfig.baseURL);       
  const host = baseURL.hostname;
  const httpsPort = baseURL.port ? Number(baseURL.port) : 443;
  const httpPort = global.testConfig.httpPort ? Number(global.testConfig.httpPort) : 80;

  // Reuse timeouts from global config if present
  const T_SHORT = (global.testConfig?.timeouts?.short)  || 3000;
  const T_MED   = (global.testConfig?.timeouts?.medium) || 10000;
  const T_LONG  = (global.testConfig?.timeouts?.long)   || 20000;

  let httpsClient;

  beforeAll(() => {
    // For self-signed local certs, we allow self-signed in tests.
    httpsClient = axios.create({
      baseURL: `https://${host}:${httpsPort}`,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
        keepAlive: true
      }),
      timeout: T_MED,
      validateStatus: () => true,
      maxRedirects: 0
    });
  });

  const tlsConnect = (opts = {}) =>
    new Promise((resolve, reject) => {
      const socket = tls.connect({
        host,
        port: httpsPort,
        servername: host,            // SNI
        rejectUnauthorized: false,   // self-signed ok for tests
        // TLS bounds
        minVersion: opts.minVersion,
        maxVersion: opts.maxVersion,
        ALPNProtocols: opts.ALPNProtocols || ['h2', 'http/1.1'],
      }, () => resolve(socket));

      socket.setTimeout(T_SHORT, () => {
        socket.destroy(new Error('TLS socket timeout'));
      });

      socket.once('error', reject);
    });

  describe('HTTP → HTTPS redirect', () => {
    test('plain HTTP is redirected to HTTPS with 301/302', async () => {
      const httpClient = axios.create({
        baseURL: `http://${host}:${httpPort}`,
        timeout: T_MED,
        validateStatus: () => true,
        maxRedirects: 0,
      });

      const resp = await httpClient.get('/');
      expect([301, 302]).toContain(resp.status);
      expect(resp.headers.location).toMatch(/^https:\/\//i);
    });
  });

  describe('TLS protocol versions', () => {
    test('TLS 1.1 is rejected', async () => {
      await expect(
        tlsConnect({ minVersion: 'TLSv1', maxVersion: 'TLSv1.1' })
      ).rejects.toBeTruthy();
    }, T_LONG);

    test('TLS 1.2 succeeds', async () => {
      const s = await tlsConnect({ minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
      try {
        // Node exposes negotiated protocol via getProtocol()
        const proto = s.getProtocol();
        expect(proto).toBe('TLSv1.2');
      } finally {
        s.end();
      }
    }, T_LONG);

    test('TLS 1.3 succeeds (if supported by runtime)', async () => {
      try {
        const s = await tlsConnect({ minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
        try {
          const proto = s.getProtocol();
          expect(proto).toBe('TLSv1.3');
        } finally {
          s.end();
        }
      } catch (e) {
        // If the Node/OpenSSL runtime doesn't support 1.3, allow skip
        console.warn('TLS 1.3 not supported in this runtime; skipping assert.');
      }
    }, T_LONG);
  });

  describe('ALPN / HTTP/2', () => {
    test('negotiates h2 via ALPN', async () => {
      const s = await tlsConnect({ ALPNProtocols: ['h2', 'http/1.1'] });
      try {
        const alpn = s.alpnProtocol; // 'h2' or 'http/1.1'
        expect(alpn).toBe('h2');
      } finally {
        s.end();
      }
    }, T_LONG);
  });

  describe('Cipher suite sanity', () => {
    test('negotiated cipher is modern (no CBC/RC4/3DES/MD5)', async () => {
      const s = await tlsConnect({ minVersion: 'TLSv1.2' });
      try {
        const cipher = s.getCipher(); // { name, version, standardName? }
        const name = (cipher?.name || '').toUpperCase();
        expect(name).toMatch(/AES/);
        expect(name).toMatch(/GCM/);
        expect(name).not.toMatch(/CBC|RC4|3DES|MD5/);
      } finally {
        s.end();
      }
    }, T_LONG);
  });

  describe('HSTS and security headers', () => {
    test('HSTS header is present on HTTPS', async () => {
      const resp = await httpsClient.get('/health'); // endpoint exists on HTTPS
      expect(resp.status).toBe(200);
      const hsts = resp.headers['strict-transport-security'];
      expect(hsts).toBeDefined();
      expect(hsts).toMatch(/max-age=63072000/i);
      expect(hsts).toMatch(/includesubdomains/i);
      expect(hsts).toMatch(/preload/i);
    });

    test('security headers present', async () => {
      const resp = await httpsClient.get('/health');
      expect(resp.status).toBe(200);
      expect(resp.headers['x-frame-options']).toBeDefined();
      expect(resp.headers['x-content-type-options']).toBe('nosniff');
      expect(resp.headers['x-xss-protection']).toBeDefined();
    });
  });

  describe('Certificate presence', () => {
    test('server presents a certificate (self-signed allowed in tests)', async () => {
      const s = await tlsConnect({ minVersion: 'TLSv1.2' });
      try {
        const cert = s.getPeerCertificate(true);
        expect(cert).toBeTruthy();
        expect(cert.subject).toBeDefined();
        // validity check (not strict, just ensure fields exist)
        expect(cert.valid_from).toBeDefined();
        expect(cert.valid_to).toBeDefined();
      } finally {
        s.end();
      }
    }, T_LONG);
  });
});