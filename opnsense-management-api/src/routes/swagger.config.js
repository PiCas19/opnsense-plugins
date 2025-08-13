const path = require('path');

module.exports = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'OPNsense Management API',
      version: '1.0.0',
      description: 'REST API wrapper for OPNsense firewall management with monitoring integration',
    },
    servers: [
      {
        url: process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: [
    path.join(__dirname, 'src/routes/*.js'),
    path.join(__dirname, 'src/routes/**/*.js'),
  ],
};