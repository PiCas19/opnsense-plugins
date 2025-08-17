// src/config/swagger.config.js
const path = require('path');

const projectRoot = path.resolve(__dirname, '..'); // -> /src
const routesGlob1 = path.resolve(projectRoot, 'routes', '*.js');
const routesGlob2 = path.resolve(projectRoot, 'routes', '**', '*.js');

module.exports = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'OPNsense Management API',
      version: process.env.npm_package_version || '1.0.0',
      description: 'REST API wrapper for OPNsense firewall management with monitoring integration',
      contact: {
        name: 'API Support',
        email: process.env.SUPPORT_EMAIL || 'support@example.com',
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT',
      },
    },
    servers: [
      { 
        url: process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: { 
          type: 'http', 
          scheme: 'bearer', 
          bearerFormat: 'JWT',
          description: 'JWT token for API authentication',
        },
        apiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-Api-Key',
          description: 'API Key for authentication',
        },
      },
      responses: {
        UnauthorizedError: {
          description: 'Authentication information is missing or invalid',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string', example: 'Unauthorized' },
                  message: { type: 'string', example: 'Invalid or missing authentication token' },
                },
              },
            },
          },
        },
        NotFoundError: {
          description: 'The specified resource was not found',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string', example: 'Not Found' },
                  message: { type: 'string', example: 'Resource not found' },
                },
              },
            },
          },
        },
        ValidationError: {
          description: 'Validation error',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string', example: 'Validation Error' },
                  message: { type: 'string', example: 'Invalid input data' },
                  details: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        field: { type: 'string' },
                        message: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      parameters: {
        RequestId: {
          name: 'X-Request-ID',
          in: 'header',
          description: 'Unique request identifier',
          schema: { type: 'string', format: 'uuid' },
        },
        CorrelationId: {
          name: 'X-Correlation-ID',
          in: 'header',
          description: 'Correlation identifier for request tracing',
          schema: { type: 'string' },
        },
      },
    },
    security: [
      { bearerAuth: [] },
      { apiKeyAuth: [] },
    ],
    tags: [
      {
        name: 'Health',
        description: 'Health check and system status endpoints',
      },
      {
        name: 'Admin',
        description: 'Administrative operations',
      },
      {
        name: 'Firewall',
        description: 'Firewall management operations',
      },
      {
        name: 'Monitoring',
        description: 'System monitoring and metrics',
      },
      {
        name: 'Policies',
        description: 'Security policy management',
      },
    ],
  },
  apis: [
    routesGlob1, 
    routesGlob2,
    // Aggiungi anche il file principale per documentare endpoint globali
    path.resolve(__dirname, '..', 'app.js'),
  ],
};