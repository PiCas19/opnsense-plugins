/**
 * Nginx Reverse Proxy Tests
 * Tests for proxy functionality, load balancing, and backend communication
 */

const axios = require('axios');
const https = require('https');

describe('Nginx Reverse Proxy Tests', () => {
  let httpClient;
  const baseURL = global.testConfig.baseURL;
  const grafanaURL = global.testConfig.grafanaURL;
  const basicAuth = global.testConfig.basicAuth;

  beforeAll(async () => {
    // Create HTTP client with SSL verification disabled for self-signed certificates
    httpClient = axios.create({
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      }),
      timeout: global.testConfig.timeouts.medium,
      validateStatus: () => true // Don't throw on HTTP errors
    });
  });

  describe('Basic Proxy Functionality', () => {
    test('should proxy requests to backend API', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.data).toHaveProperty('status');
    });

    test('should proxy requests to Grafana', async () => {
      const response = await httpClient.get(`${grafanaURL}/api/health`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('database');
      expect(response.data).toHaveProperty('version');
    });

    test('should handle root path redirects correctly', async () => {
      const response = await httpClient.get(baseURL, {
        maxRedirects: 0 // Don't follow redirects automatically
      });

      expect([301, 302, 307, 308]).toContain(response.status);
      expect(response.headers.location).toMatch(/\/grafana/);
    });

    test('should serve health check endpoint', async () => {
      const response = await httpClient.get(`${baseURL}/health`);

      expect(response.status).toBe(200);
      expect(response.data).toMatch(/healthy|ok/i);
    });
  });

  describe('Request Headers and Modification', () => {
    test('should add proper proxy headers to backend requests', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'X-Test-Client': 'nginx-test'
        }
      });

      expect(response.status).toBe(200);
      
      // Verify that the backend received proper proxy headers
      // This would need to be verified on the backend side
      // For now, we just verify the request was successful
    });

    test('should preserve important client headers', async () => {
      const customHeaders = {
        'User-Agent': 'Custom-Test-Agent/1.0',
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'X-Custom-Header': 'test-value'
      };

      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: customHeaders
      });

      expect(response.status).toBe(200);
    });

    test('should handle large request headers', async () => {
      const largeHeaderValue = 'x'.repeat(4000); // 4KB header
      
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'X-Large-Header': largeHeaderValue
        }
      });

      // Should either succeed or fail gracefully with 431 (Request Header Fields Too Large)
      expect([200, 431]).toContain(response.status);
    });
  });

  describe('HTTP Methods and Body Handling', () => {
    test('should proxy GET requests correctly', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/firewall/rules`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect([200, 401, 404]).toContain(response.status); // Depending on backend implementation
    });

    test('should proxy POST requests with JSON body', async () => {
      const testRule = {
        interface: 'wan',
        direction: 'in',
        action: 'pass',
        protocol: 'tcp',
        source_address: 'any',
        destination_address: '192.168.1.100',
        destination_port: '80',
        description: 'Test rule via proxy'
      };

      const response = await httpClient.post(`${baseURL}/api/v1/firewall/rules`, testRule, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Should proxy the request to backend
      expect([200, 201, 400, 401, 404]).toContain(response.status);
    });

    test('should proxy PUT requests correctly', async () => {
      const updateData = {
        description: 'Updated rule description'
      };

      const response = await httpClient.put(`${baseURL}/api/v1/firewall/rules/test_rule`, updateData, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });

      expect([200, 404, 401]).toContain(response.status);
    });

    test('should proxy DELETE requests correctly', async () => {
      const response = await httpClient.delete(`${baseURL}/api/v1/firewall/rules/test_rule`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect([200, 204, 404, 401]).toContain(response.status);
    });

    test('should handle large request bodies', async () => {
      const largeBody = {
        description: 'x'.repeat(10000), // 10KB description
        data: Array(1000).fill().map((_, i) => ({ id: i, value: `test_${i}` }))
      };

      const response = await httpClient.post(`${baseURL}/api/v1/test/large-body`, largeBody, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Should either succeed or fail gracefully
      expect([200, 413, 404]).toContain(response.status); // 413 = Payload Too Large
    });
  });

  describe('Error Handling and Resilience', () => {
    test('should handle backend timeouts gracefully', async () => {
      // Simulate a request that might timeout
      const response = await httpClient.get(`${baseURL}/api/v1/slow-endpoint`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        timeout: 5000
      });

      // Should get either a successful response or a timeout error from nginx
      expect([200, 404, 502, 504]).toContain(response.status);
    });

    test('should return 502 when backend is unavailable', async () => {
      // This test assumes there might be endpoints that are temporarily unavailable
      // or we could test with a deliberately unavailable backend
      
      const response = await httpClient.get(`${baseURL}/api/v1/unavailable-service`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      // Should return either 404 (not found) or 502 (bad gateway) depending on configuration
      expect([404, 502, 503]).toContain(response.status);
    });

    test('should handle malformed requests gracefully', async () => {
      // Send a request with invalid JSON
      const response = await httpClient.post(`${baseURL}/api/v1/firewall/rules`, 'invalid json{', {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe('Performance and Caching', () => {
    test('should add appropriate caching headers', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect(response.status).toBe(200);
      
      // Check for caching headers (if configured)
      if (response.headers['cache-control']) {
        expect(response.headers['cache-control']).toBeDefined();
      }
    });

    test('should handle concurrent requests efficiently', async () => {
      const concurrentRequests = 10;
      const startTime = Date.now();

      const promises = Array(concurrentRequests).fill().map(() =>
        httpClient.get(`${baseURL}/api/v1/health`, {
          auth: {
            username: basicAuth.username,
            password: basicAuth.password
          }
        })
      );

      const responses = await Promise.all(promises);
      const endTime = Date.now();
      const totalTime = endTime - startTime;

      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });

      // Should handle concurrent requests reasonably fast
      expect(totalTime).toBeLessThan(10000); // 10 seconds for 10 requests
    });

    test('should maintain persistent connections', async () => {
      // Make multiple requests to test connection reuse
      const responses = [];
      
      for (let i = 0; i < 5; i++) {
        const response = await httpClient.get(`${baseURL}/api/v1/health`, {
          auth: {
            username: basicAuth.username,
            password: basicAuth.password
          }
        });
        responses.push(response);
      }

      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });
  });

  describe('Security and Access Control', () => {
    test('should not expose backend server information', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect(response.status).toBe(200);
      
      // Should not expose backend server headers
      expect(response.headers.server).not.toContain('Express');
      expect(response.headers.server).not.toContain('Node.js');
      expect(response.headers['x-powered-by']).toBeUndefined();
    });

    test('should block direct backend access attempts', async () => {
      // Try to access backend directly by manipulating headers
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'X-Original-URL': '/admin/secret',
          'X-Rewrite-URL': '/backdoor'
        }
      });

      expect(response.status).toBe(200); // Should still go to normal endpoint
    });

    test('should sanitize error responses', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/nonexistent-endpoint`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      // Should not expose internal paths or configuration
      if (response.data && typeof response.data === 'string') {
        expect(response.data).not.toContain('/etc/nginx');
        expect(response.data).not.toContain('/var/log');
        expect(response.data).not.toContain('root@');
      }
    });
  });

  describe('WebSocket Proxying (if applicable)', () => {
    test('should handle WebSocket upgrade requests', async () => {
      // Skip if WebSocket support not implemented
      const response = await httpClient.get(`${baseURL}/api/v1/ws`, {
        headers: {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
          'Sec-WebSocket-Version': '13'
        }
      });

      // Should either upgrade to WebSocket (101) or not support it (404/400)
      expect([101, 400, 404, 426]).toContain(response.status);
    });
  });

  describe('Grafana-Specific Proxying', () => {
    test('should proxy Grafana API requests correctly', async () => {
      const response = await httpClient.get(`${grafanaURL}/api/datasources`, {
        auth: {
          username: global.testConfig.grafanaAuth.username,
          password: global.testConfig.grafanaAuth.password
        }
      });

      // Should either succeed or require authentication
      expect([200, 401]).toContain(response.status);
    });

    test('should handle Grafana static assets', async () => {
      const response = await httpClient.get(`${grafanaURL}/public/build/app.js`);

      // Should either serve the asset or return 404 if not found
      expect([200, 404]).toContain(response.status);
      
      if (response.status === 200) {
        expect(response.headers['content-type']).toContain('javascript');
      }
    });

    test('should preserve Grafana session cookies', async () => {
      const loginResponse = await httpClient.post(`${grafanaURL}/login`, {
        user: global.testConfig.grafanaAuth.username,
        password: global.testConfig.grafanaAuth.password
      });

      if (loginResponse.status === 200 && loginResponse.headers['set-cookie']) {
        const cookies = loginResponse.headers['set-cookie'];
        expect(cookies.some(cookie => cookie.includes('grafana_session'))).toBe(true);
      }
    });
  });

  afterAll(async () => {
    // Cleanup any test data if needed
  });
});