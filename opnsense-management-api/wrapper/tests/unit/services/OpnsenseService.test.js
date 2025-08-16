// OpnsenseService unit tests

jest.mock('../../../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock configurazione OPNsense
jest.mock('../../../src/config/opnsense', () => ({
  baseURL: 'https://opnsense.local:8443',
  apiKey: 'APIKEY123',
  apiSecret: 'SECRET456',
  timeout: 5000,
}));

// Mock axios client
const axiosInstance = {
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
};
jest.mock('axios', () => ({
  create: jest.fn(() => axiosInstance),
}));

const logger = require('../../../src/utils/logger');
const OpnsenseService = require('../../../src/services/OpnsenseService');
const config = require('../../../src/config/opnsense');
const axios = require('axios');

describe('OpnsenseService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('inizializza axios con baseURL, timeout e headers di auth', () => {
    // Import side-effect già avvenuto; verifichiamo la create()
    expect(axios.create).toHaveBeenCalledWith(
      expect.objectContaining({
        baseURL: config.baseURL,
        timeout: config.timeout,
        httpsAgent: expect.any(Object), // spesso rejectUnauthorized: false in dev
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Authorization: expect.stringMatching(/(Bearer|Basic|ApiKey)/i),
        }),
      })
    );
  });

  describe('request wrapper', () => {
    it('GET /firewall/rules ritorna dati', async () => {
      axiosInstance.get.mockResolvedValue({ status: 200, data: [{ rule_id: 1 }] });
      const res = await OpnsenseService.listFirewallRules();
      expect(axiosInstance.get).toHaveBeenCalledWith('/api/firewall/rules');
      expect(res).toEqual([{ rule_id: 1 }]);
    });

    it('POST toggle rule mappa status non-2xx in errore', async () => {
      axiosInstance.post.mockResolvedValue({ status: 403, data: { message: 'Forbidden' } });
      await expect(OpnsenseService.toggleRule(5, true)).rejects.toThrow(/403|forbidden/i);
      expect(logger.error).toHaveBeenCalled();
    });

    it('bulk enable/disable chiamano endpoint corretti', async () => {
      axiosInstance.post.mockResolvedValue({ status: 200, data: { updated: [1, 2] } });
      await OpnsenseService.bulkEnable([1, 2]);
      expect(axiosInstance.post).toHaveBeenCalledWith('/api/firewall/rules/bulk/enable', { ids: [1, 2] });

      await OpnsenseService.bulkDisable([3]);
      expect(axiosInstance.post).toHaveBeenCalledWith('/api/firewall/rules/bulk/disable', { ids: [3] });
    });

    it('reload e backup usano gli endpoint previsti', async () => {
      axiosInstance.post.mockResolvedValue({ status: 200, data: { ok: true } });
      await OpnsenseService.reload();
      expect(axiosInstance.post).toHaveBeenCalledWith('/api/firewall/reload', {});

      axiosInstance.get.mockResolvedValue({ status: 200, data: '{"rules":[]}' });
      const buf = await OpnsenseService.backupRules();
      expect(axiosInstance.get).toHaveBeenCalledWith('/api/firewall/backup', { responseType: 'arraybuffer' });
      expect(Buffer.isBuffer(buf) || typeof buf === 'string').toBe(true);
    });
  });

  it('propaga errori di rete (axios) con logging', async () => {
    axiosInstance.get.mockRejectedValue(new Error('ECONNREFUSED'));
    await expect(OpnsenseService.listFirewallRules()).rejects.toThrow(/ECONNREFUSED/i);
    expect(logger.error).toHaveBeenCalled();
  });
});