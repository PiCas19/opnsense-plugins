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

// Mock User model
jest.mock('../../../src/models/User', () => ({
  findByPk: jest.fn(),
  findOne: jest.fn(),
}));

const User = require('../../../src/models/User');

describe('Auth Middleware', () => {
  beforeEach(() => {
    resetMocks();
  });

  describe('generateToken', () => {
    it('should generate a valid JWT token', () => {
      const payload = { id: 1, username: 'testuser' };
      const token = generateToken(payload);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      // Verify token can be decoded
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      expect(decoded.id).toBe(payload.id);
      expect(decoded.username).toBe(payload.username);
    });

    it('should include correct issuer and audience', () => {
      const payload = { id: 1 };
      const token = generateToken(payload);
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      expect(decoded.iss).toBe('opnsense-management-api');
      expect(decoded.aud).toBe('opnsense-users');
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid token', () => {
      const payload = { id: 1, username: 'testuser' };
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

    it('should throw error for expired token', () => {
      const expiredToken = jwt.sign(
        { id: 1 },
        process.env.JWT_SECRET,
        { expiresIn: '1ms', issuer: 'opnsense-management-api', audience: 'opnsense-users' }
      );
      
      // Wait for token to expire
      setTimeout(() => {
        expect(() => {
          verifyToken(expiredToken);
        }).toThrow('Invalid token');
      }, 10);
    });
  });

  describe('hashPassword', () => {
    it('should hash password correctly', async () => {
      const password = 'testPassword123!';
      const hash = await hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(50);
    });

    it('should generate different hashes for same password', async () => {
      const password = 'testPassword123!';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('comparePassword', () => {
    it('should return true for correct password', async () => {
      const password = 'testPassword123!';
      const hash = await hashPassword(password);
      
      const isValid = await comparePassword(password, hash);
      expect(isValid).toBe(true);
    });

    it('should return false for incorrect password', async () => {
      const password = 'testPassword123!';
      const wrongPassword = 'wrongPassword123!';
      const hash = await hashPassword(password);
      
      const isValid = await comparePassword(wrongPassword, hash);
      expect(isValid).toBe(false);
    });
  });

  describe('authenticate middleware', () => {
    it('should authenticate valid token and user', async () => {
      const user = mockUser();
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
      const token = generateToken({ id: 999 });
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
      const user = mockUser({ is_active: false });
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
  });

  describe('authorize middleware', () => {
    it('should allow access with correct permission', () => {
      const req = mockRequest({
        user: mockUser({ role: 'admin' }),
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
      const req = mockRequest({
        user: mockUser({ role: 'viewer' }),
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
      const req = mockRequest({
        user: mockUser({ role: 'admin' }),
        permissions: [PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE]
      });
      const res = mockResponse();
      const next = mockNext();
      
      const middleware = authorize(PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE);
      middleware(req, res, next);
      
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
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
  });
});