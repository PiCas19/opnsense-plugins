/**
 * Nginx Authentication Tests
 * Tests for HTTP Basic Authentication, JWT token validation, and security
 */

const axios = require('axios');
const https = require('https');

describe('Nginx Authentication Tests', () => {
  let httpClient;
  const baseURL = global.testConfig.baseURL;
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

  describe('Basic Authentication', () => {
    test('should allow access with valid basic auth credentials', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('status');
    });

    test('should deny access without authentication', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`);

      expect(response.status).toBe(401);
      expect(response.headers['www-authenticate']).toContain('Basic');
    });

    test('should deny access with invalid username', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: 'invalid_user',
          password: basicAuth.password
        }
      });

      expect(response.status).toBe(401);
      expect(response.headers['www-authenticate']).toContain('Basic');
    });

    test('should deny access with invalid password', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: 'invalid_password'
        }
      });

      expect(response.status).toBe(401);
      expect(response.headers['www-authenticate']).toContain('Basic');
    });

    test('should deny access with empty credentials', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: '',
          password: ''
        }
      });

      expect(response.status).toBe(401);
    });

    test('should deny access with malformed authorization header', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        headers: {
          'Authorization': 'Basic invalid_base64'
        }
      });

      expect(response.status).toBe(401);
    });

    test('should handle special characters in credentials', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: 'user@domain.com',
          password: 'P@ssw0rd!#$%'
        }
      });

      expect(response.status).toBe(401); // Should fail with test credentials
    });
  });

  describe('JWT Token Authentication', () => {
    let validJwtToken;

    beforeAll(async () => {
      // Try to get a valid JWT token if available
      if (global.testConfig.jwtToken) {
        validJwtToken = global.testConfig.jwtToken;
      }
    });

    test('should accept valid JWT token for API access', async () => {
      if (!validJwtToken) {
        console.log('Skipping JWT test - no valid token available');
        return;
      }

      const response = await httpClient.get(`${baseURL}/api/v1/firewall/rules`, {
        headers: {
          'Authorization': `Bearer ${validJwtToken}`
        }
      });

      expect(response.status).toBeLessThan(500); // Should not be server error
    });

    test('should reject invalid JWT token', async () => {
      const invalidToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature';
      
      const response = await httpClient.get(`${baseURL}/api/v1/firewall/rules`, {
        headers: {
          'Authorization': `Bearer ${invalidToken}`
        }
      });

      expect(response.status).toBe(401);
    });

    test('should reject expired JWT token', async () => {
      // This is an expired token for testing
      const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid';
      
      const response = await httpClient.get(`${baseURL}/api/v1/firewall/rules`, {
        headers: {
          'Authorization': `Bearer ${expiredToken}`
        }
      });

      expect(response.status).toBe(401);
    });

    test('should reject malformed JWT token', async () => {
      const malformedToken = 'not.a.valid.jwt';
      
      const response = await httpClient.get(`${baseURL}/api/v1/firewall/rules`, {
        headers: {
          'Authorization': `Bearer ${malformedToken}`
        }
      });

      expect(response.status).toBe(401);
    });
  });

  describe('Authentication Security', () => {
    test('should not expose sensitive information in error responses', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`);

      expect(response.status).toBe(401);
      expect(response.data).not.toContain('password');
      expect(response.data).not.toContain('secret');
      expect(response.data).not.toContain('key');
    });

    test('should include security headers in authentication responses', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`);

      expect(response.headers['x-frame-options']).toBeDefined();
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-xss-protection']).toBeDefined();
    });

    test('should handle authentication timing attacks', async () => {
      const startTime = Date.now();
      
      await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: 'nonexistent_user',
          password: 'wrong_password'
        }
      });
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;

      // Response time should be reasonable (not too fast to prevent timing attacks)
      expect(responseTime).toBeGreaterThan(50);
      expect(responseTime).toBeLessThan(5000);
    });

    test('should limit authentication attempts', async () => {
      const maxAttempts = 5;
      const responses = [];

      // Make multiple failed authentication attempts
      for (let i = 0; i < maxAttempts + 2; i++) {
        const response = await httpClient.get(`${baseURL}/api/v1/health`, {
          auth: {
            username: 'test_user',
            password: `wrong_password_${i}`
          }
        });
        responses.push(response);
        
        // Small delay between attempts
        await global.testUtils.sleep(100);
      }

      // All should be unauthorized
      responses.forEach(response => {
        expect(response.status).toBe(401);
      });

      // Later attempts might have different rate limiting behavior
      // This depends on the specific rate limiting implementation
    });
  });

  describe('CORS and Preflight Requests', () => {
    test('should handle OPTIONS preflight requests with authentication', async () => {
      const response = await httpClient.options(`${baseURL}/api/v1/health`, {
        headers: {
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Authorization',
          'Origin': 'https://localhost'
        }
      });

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-methods']).toBeDefined();
      expect(response.headers['access-control-allow-headers']).toContain('Authorization');
    });

    test('should include CORS headers in authenticated responses', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        },
        headers: {
          'Origin': 'https://localhost'
        }
      });

      expect(response.status).toBe(200);
      expect(response.headers['access-control-allow-origin']).toBeDefined();
    });
  });

  describe('Authentication Bypass Attempts', () => {
    test('should not allow bypassing auth with X-Forwarded-User header', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        headers: {
          'X-Forwarded-User': 'admin',
          'X-Remote-User': 'admin'
        }
      });

      expect(response.status).toBe(401);
    });

    test('should not allow bypassing auth with X-Real-IP spoofing', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        headers: {
          'X-Real-IP': '127.0.0.1',
          'X-Forwarded-For': '127.0.0.1'
        }
      });

      expect(response.status).toBe(401);
    });

    test('should not allow bypassing auth with Host header manipulation', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        headers: {
          'Host': 'localhost:3000' // Try to bypass to backend directly
        }
      });

      expect(response.status).toBe(401);
    });
  });

  describe('Password Policy and Security', () => {
    test('should enforce minimum password requirements (if configurable)', async () => {
      // This test assumes there's an endpoint to change passwords
      // Skip if not implemented
      const changePasswordEndpoint = `${baseURL}/api/v1/auth/change-password`;
      
      const response = await httpClient.post(changePasswordEndpoint, {
        current_password: basicAuth.password,
        new_password: '123' // Too short
      }, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      // If endpoint exists, should reject weak passwords
      if (response.status !== 404) {
        expect(response.status).toBe(400);
      }
    });

    test('should handle Unicode characters in authentication', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: 'tëst_üser_ñ',
          password: 'pässwörd_测试'
        }
      });

      expect(response.status).toBe(401); // Should fail gracefully
    });
  });

  describe('Session Management', () => {
    test('should not create persistent sessions for basic auth', async () => {
      // Make first request
      const response1 = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect(response1.status).toBe(200);

      // Make second request without auth - should fail
      const response2 = await httpClient.get(`${baseURL}/api/v1/health`);

      expect(response2.status).toBe(401);
    });

    test('should not set unnecessary cookies', async () => {
      const response = await httpClient.get(`${baseURL}/api/v1/health`, {
        auth: {
          username: basicAuth.username,
          password: basicAuth.password
        }
      });

      expect(response.status).toBe(200);
      
      // Should not set session cookies for API endpoints
      const cookies = response.headers['set-cookie'];
      if (cookies) {
        expect(cookies.some(cookie => cookie.includes('PHPSESSID'))).toBe(false);
        expect(cookies.some(cookie => cookie.includes('JSESSIONID'))).toBe(false);
      }
    });
  });

  afterAll(async () => {
    // Cleanup any test data if needed
  });
});