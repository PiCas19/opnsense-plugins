// tests/unit/middleware/auth.test.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const {
  authenticate,
  authorize,
  generateToken,
  verifyToken,
  hashPassword,
  comparePassword,
  PERMISSIONS,
  ROLES,
} = require('../../../src/middleware/auth');

// Mock JWT secret for testing
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing';

// Mock User model
jest.mock('../../../src/models/User', () => ({
  findByPk: jest.fn(),
  findOne: jest.fn(),
}));

const User = require('../../../src/models/User');

describe('Auth Middleware', () => {
  // Helper functions usando fixtures globali
  const mockRequest = (overrides = {}) => {
    return {
      headers: {},
      user: null,
      permissions: [],
      ip: fixtures.random.ip(),
      originalUrl: '/api/test',
      method: 'GET',
      ...overrides
    };
  };

  const mockResponse = () => ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    setHeader: jest.fn(),
    locals: {}
  });

  const mockNext = () => jest.fn();

  const mockUser = (overrides = {}) => {
    const testUser = fixtures.createTestUser('admin', overrides);
    return {
      ...testUser,
      is_active: true,
      last_login: new Date(),
      ...overrides
    };
  };

  const resetMocks = () => {
    jest.clearAllMocks();
    User.findByPk.mockClear();
    User.findOne.mockClear();
  };

  beforeEach(() => {
    resetMocks();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in auth test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  describe('generateToken', () => {
    it('should generate a valid JWT token', () => {
      const testUser = fixtures.createTestUser('admin');
      const payload = { id: testUser.id, username: testUser.username };
      const token = generateToken(payload);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      // Verify token can be decoded
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      expect(decoded.id).toBe(payload.id);
      expect(decoded.username).toBe(payload.username);
    });

    it('should include correct issuer and audience', () => {
      const testUser = fixtures.createTestUser('operator');
      const payload = { id: testUser.id };
      const token = generateToken(payload);
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      expect(decoded.iss).toBe('opnsense-management-api');
      expect(decoded.aud).toBe('opnsense-users');
    });

    it('should work with fixture JWT tokens', () => {
      const testUser = fixtures.createTestUser('admin');
      const fixtureToken = fixtures.createTestJWTToken({
        id: testUser.id,
        username: testUser.username,
        role: testUser.role
      });
      
      expect(fixtureToken).toBeDefined();
      expect(fixtureToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid token', () => {
      const testUser = fixtures.createTestUser('viewer');
      const payload = { id: testUser.id, username: testUser.username };
      const token = generateToken(payload);
      
      const decoded = verifyToken(token);
      expect(decoded.id).toBe(payload.id);
      expect(decoded.username).toBe(payload.username);
    });

    it('should throw error for invalid token', () => {
      expect(() => {
        verifyToken('invalid-token');
      }).toThrow('Invalid token');
    });

    it('should throw error for expired token', (done) => {
      const testUser = fixtures.createTestUser('admin');
      const expiredToken = jwt.sign(
        { id: testUser.id },
        process.env.JWT_SECRET,
        { expiresIn: '1ms', issuer: 'opnsense-management-api', audience: 'opnsense-users' }
      );
      
      // Wait for token to expire
      setTimeout(() => {
        expect(() => {
          verifyToken(expiredToken);
        }).toThrow('Invalid token');
        done();
      }, 10);
    });

    it('should handle malformed tokens gracefully', () => {
      const malformedTokens = [
        'malformed.token',
        'not.a.valid.jwt.token',
        '',
        null,
        undefined
      ];

      malformedTokens.forEach(token => {
        expect(() => {
          verifyToken(token);
        }).toThrow('Invalid token');
      });
    });
  });

  describe('hashPassword', () => {
    it('should hash password correctly', async () => {
      const password = fixtures.random.string(12) + '!123';
      const hash = await hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(50);
    });

    it('should generate different hashes for same password', async () => {
      const password = `test-${fixtures.random.string(8)}!123`;
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });

    it('should handle various password formats', async () => {
      const passwords = [
        'simple123',
        'Complex!P@ssw0rd',
        fixtures.random.string(20),
        'пароль123', // Unicode
        '特殊密码123' // Chinese characters
      ];

      for (const password of passwords) {
        const hash = await hashPassword(password);
        expect(hash).toBeDefined();
        expect(hash.length).toBeGreaterThan(50);
      }
    });
  });

  describe('comparePassword', () => {
    it('should return true for correct password', async () => {
      const password = `test-${fixtures.random.string(8)}!Password123`;
      const hash = await hashPassword(password);
      
      const isValid = await comparePassword(password, hash);
      expect(isValid).toBe(true);
    });

    it('should return false for incorrect password', async () => {
      const password = `correct-${fixtures.random.string(8)}!123`;
      const wrongPassword = `wrong-${fixtures.random.string(8)}!123`;
      const hash = await hashPassword(password);
      
      const isValid = await comparePassword(wrongPassword, hash);
      expect(isValid).toBe(false);
    });

    it('should handle edge cases', async () => {
      const password = 'testPassword123!';
      const hash = await hashPassword(password);
      
      // Test empty strings
      expect(await comparePassword('', hash)).toBe(false);
      expect(await comparePassword(password, '')).toBe(false);
      
      // Test null/undefined
      expect(await comparePassword(null, hash)).toBe(false);
      expect(await comparePassword(password, null)).toBe(false);
    });
  });

  describe('authenticate middleware', () => {
    it('should authenticate valid token and user', async () => {
      const testUser = fixtures.createTestUser('admin');
      const user = mockUser(testUser);
      const token = generateToken({ id: user.id });
      
      User.findByPk.mockResolvedValue(user);
      
      const req = mockRequest({
        headers: { authorization: `Bearer ${token}` }
      });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(req.user).toEqual(user);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject request without token', async () => {
      const req = mockRequest({ headers: {} });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Authentication token required',
        code: 'TOKEN_MISSING',
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject invalid token', async () => {
      const req = mockRequest({
        headers: { authorization: 'Bearer invalid-token' }
      });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Invalid token',
        code: 'TOKEN_INVALID',
      });
    });

    it('should reject token for non-existent user', async () => {
      const nonExistentId = fixtures.random.number(9000, 9999);
      const token = generateToken({ id: nonExistentId });
      User.findByPk.mockResolvedValue(null);
      
      const req = mockRequest({
        headers: { authorization: `Bearer ${token}` }
      });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    });

    it('should reject token for inactive user', async () => {
      const testUser = fixtures.createTestUser('operator');
      const user = mockUser({ ...testUser, is_active: false });
      const token = generateToken({ id: user.id });
      
      User.findByPk.mockResolvedValue(user);
      
      const req = mockRequest({
        headers: { authorization: `Bearer ${token}` }
      });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'User account is disabled',
        code: 'USER_DISABLED',
      });
    });

    it('should handle different authorization header formats', async () => {
      const testUser = fixtures.createTestUser('admin');
      const user = mockUser(testUser);
      const token = generateToken({ id: user.id });
      
      User.findByPk.mockResolvedValue(user);

      const headerFormats = [
        `Bearer ${token}`,
        `bearer ${token}`,
        `BEARER ${token}`,
        token // Without Bearer prefix (should fail)
      ];

      for (let i = 0; i < headerFormats.length; i++) {
        const req = mockRequest({
          headers: { authorization: headerFormats[i] }
        });
        const res = mockResponse();
        const next = mockNext();
        
        await authenticate(req, res, next);
        
        if (i < 3) { // Bearer formats should work
          expect(next).toHaveBeenCalled();
        } else { // Without Bearer should fail
          expect(res.status).toHaveBeenCalledWith(401);
        }
        
        // Reset mocks for next iteration
        resetMocks();
        User.findByPk.mockResolvedValue(user);
      }
    });

    it('should handle database errors gracefully', async () => {
      const testUser = fixtures.createTestUser('admin');
      const token = generateToken({ id: testUser.id });
      const dbError = fixtures.createHTTPError(500, 'Database connection failed');
      
      User.findByPk.mockRejectedValue(dbError);
      
      const req = mockRequest({
        headers: { authorization: `Bearer ${token}` }
      });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Authentication service unavailable',
        code: 'AUTH_SERVICE_ERROR',
      });
    });
  });

  describe('authorize middleware', () => {
    it('should allow access with correct permission', () => {
      const testUser = fixtures.createTestUser('admin');
      const req = mockRequest({
        user: mockUser(testUser),
        permissions: [PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE]
      });
      const res = mockResponse();
      const next = mockNext();
      
      const middleware = authorize(PERMISSIONS.FIREWALL_READ);
      middleware(req, res, next);
      
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should deny access without permission', () => {
      const testUser = fixtures.createTestUser('viewer');
      const req = mockRequest({
        user: mockUser(testUser),
        permissions: [PERMISSIONS.FIREWALL_READ]
      });
      const res = mockResponse();
      const next = mockNext();
      
      const middleware = authorize(PERMISSIONS.FIREWALL_WRITE);
      middleware(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: [PERMISSIONS.FIREWALL_WRITE],
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should deny access without authentication', () => {
      const req = mockRequest({ user: null });
      const res = mockResponse();
      const next = mockNext();
      
      const middleware = authorize(PERMISSIONS.FIREWALL_READ);
      middleware(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    });

    it('should check multiple permissions correctly', () => {
      const testUser = fixtures.createTestUser('admin');
      const req = mockRequest({
        user: mockUser(testUser),
        permissions: [PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE]
      });
      const res = mockResponse();
      const next = mockNext();
      
      const middleware = authorize(PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE);
      middleware(req, res, next);
      
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should work with different user roles from fixtures', () => {
      const testCases = [
        {
          role: 'admin',
          permissions: ['firewall:read', 'firewall:write', 'system:read', 'system:write'],
          requiredPermission: PERMISSIONS.FIREWALL_WRITE,
          shouldPass: true
        },
        {
          role: 'operator',
          permissions: ['firewall:read', 'firewall:write'],
          requiredPermission: PERMISSIONS.SYSTEM_WRITE || 'system:write',
          shouldPass: false
        },
        {
          role: 'viewer',
          permissions: ['firewall:read', 'system:read'],
          requiredPermission: PERMISSIONS.FIREWALL_WRITE,
          shouldPass: false
        }
      ];

      testCases.forEach(({ role, permissions, requiredPermission, shouldPass }) => {
        const testUser = fixtures.createTestUser(role);
        const req = mockRequest({
          user: mockUser(testUser),
          permissions: permissions
        });
        const res = mockResponse();
        const next = mockNext();
        
        const middleware = authorize(requiredPermission);
        middleware(req, res, next);
        
        if (shouldPass) {
          expect(next).toHaveBeenCalled();
          expect(res.status).not.toHaveBeenCalled();
        } else {
          expect(res.status).toHaveBeenCalledWith(403);
          expect(next).not.toHaveBeenCalled();
        }
        
        // Reset for next test case
        resetMocks();
      });
    });
  });

  describe('ROLES and PERMISSIONS', () => {
    it('should have correct role definitions', () => {
      expect(ROLES).toEqual({
        ADMIN: 'admin',
        OPERATOR: 'operator',
        VIEWER: 'viewer',
        API_USER: 'api_user',
      });
    });

    it('should have firewall permissions defined', () => {
      expect(PERMISSIONS.FIREWALL_READ).toBe('firewall:read');
      expect(PERMISSIONS.FIREWALL_WRITE).toBe('firewall:write');
      expect(PERMISSIONS.FIREWALL_DELETE).toBe('firewall:delete');
      expect(PERMISSIONS.FIREWALL_TOGGLE).toBe('firewall:toggle');
    });

    it('should have monitoring permissions defined', () => {
      expect(PERMISSIONS.MONITORING_READ).toBe('monitoring:read');
      expect(PERMISSIONS.MONITORING_WRITE).toBe('monitoring:write');
    });

    it('should match fixture user roles', () => {
      const adminUser = fixtures.createTestUser('admin');
      const operatorUser = fixtures.createTestUser('operator');
      const viewerUser = fixtures.createTestUser('viewer');

      expect(adminUser.role).toBe(ROLES.ADMIN);
      expect(operatorUser.role).toBe(ROLES.OPERATOR);
      expect(viewerUser.role).toBe(ROLES.VIEWER);
    });

    it('should validate permissions structure from fixtures', () => {
      const adminUser = fixtures.createTestUser('admin');
      const operatorUser = fixtures.createTestUser('operator');
      const viewerUser = fixtures.createTestUser('viewer');

      // Admin should have write permissions
      expect(adminUser.permissions).toContain('firewall:write');
      expect(adminUser.permissions).toContain('system:write');

      // Operator should have some write permissions
      expect(operatorUser.permissions).toContain('firewall:write');
      expect(operatorUser.permissions).not.toContain('system:write');

      // Viewer should only have read permissions
      expect(viewerUser.permissions).toContain('firewall:read');
      expect(viewerUser.permissions).not.toContain('firewall:write');
    });
  });

  describe('Integration Tests with Fixtures', () => {
    it('should authenticate user from test data', async () => {
      const testUser = fixtures.createTestUser('operator');
      const user = mockUser(testUser);
      const token = generateToken({ 
        id: user.id, 
        username: user.username,
        role: user.role 
      });
      
      User.findByPk.mockResolvedValue(user);
      
      const req = mockRequest({
        headers: { authorization: `Bearer ${token}` },
        ip: fixtures.random.ip()
      });
      const res = mockResponse();
      const next = mockNext();
      
      await authenticate(req, res, next);
      
      expect(req.user.username).toBe(testUser.username);
      expect(req.user.role).toBe(testUser.role);
      expect(req.user.permissions).toEqual(testUser.permissions);
    });

    it('should handle multiple users with different permissions', async () => {
      const users = [
        fixtures.createTestUser('admin'),
        fixtures.createTestUser('operator'),
        fixtures.createTestUser('viewer')
      ];

      for (const testUser of users) {
        const user = mockUser(testUser);
        const token = generateToken({ id: user.id });
        
        User.findByPk.mockResolvedValue(user);
        
        const req = mockRequest({
          headers: { authorization: `Bearer ${token}` },
          user: user,
          permissions: user.permissions
        });
        const res = mockResponse();
        const next = mockNext();
        
        // Test authorization for firewall write
        const middleware = authorize(PERMISSIONS.FIREWALL_WRITE);
        middleware(req, res, next);
        
        if (user.role === 'admin' || user.role === 'operator') {
          expect(next).toHaveBeenCalled();
        } else {
          expect(res.status).toHaveBeenCalledWith(403);
        }
        
        resetMocks();
      }
    });

    it('should work with fixture JWT tokens', () => {
      const testUser = fixtures.createTestUser('admin');
      const fixtureToken = fixtures.createTestJWTToken({
        sub: testUser.id.toString(),
        username: testUser.username,
        role: testUser.role
      });

      // Fixture tokens are for testing only, so we just validate format
      expect(fixtureToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
      
      // In real app, you'd decode and use the payload
      const parts = fixtureToken.split('.');
      expect(parts).toHaveLength(3);
    });

    it('should handle password operations with test users', async () => {
      const testUser = fixtures.createTestUser('admin');
      const plainPassword = 'TestPassword123!';
      
      // Hash the password
      const hashedPassword = await hashPassword(plainPassword);
      
      // Verify it matches
      const isValid = await comparePassword(plainPassword, hashedPassword);
      expect(isValid).toBe(true);
      
      // Verify wrong password fails
      const wrongPassword = 'WrongPassword123!';
      const isInvalid = await comparePassword(wrongPassword, hashedPassword);
      expect(isInvalid).toBe(false);
    });
  });

  describe('Security Tests', () => {
    it('should reject tokens with wrong secret', () => {
      const testUser = fixtures.createTestUser('admin');
      const maliciousToken = jwt.sign(
        { id: testUser.id, username: testUser.username },
        'wrong-secret'
      );

      expect(() => {
        verifyToken(maliciousToken);
      }).toThrow('Invalid token');
    });

    it('should reject tokens with modified payload', () => {
      const testUser = fixtures.createTestUser('viewer');
      const validToken = generateToken({ id: testUser.id, role: 'viewer' });
      
      // Try to modify the token to escalate privileges
      const parts = validToken.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64'));
      payload.role = 'admin'; // Try to escalate
      
      const modifiedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
      const modifiedToken = `${parts[0]}.${modifiedPayload}.${parts[2]}`;
      
      expect(() => {
        verifyToken(modifiedToken);
      }).toThrow('Invalid token');
    });

    it('should handle timing attacks on password comparison', async () => {
      const testUser = fixtures.createTestUser('admin');
      const password = 'CorrectPassword123!';
      const hash = await hashPassword(password);
      
      // Measure time for correct password
      const start1 = process.hrtime();
      await comparePassword(password, hash);
      const time1 = process.hrtime(start1);
      
      // Measure time for wrong password
      const start2 = process.hrtime();
      await comparePassword('WrongPassword123!', hash);
      const time2 = process.hrtime(start2);
      
      // Times should be relatively similar (bcrypt is designed to be constant-time)
      const diff = Math.abs(time1[1] - time2[1]);
      expect(diff).toBeLessThan(50000000); // 50ms difference max
    });
  });
});