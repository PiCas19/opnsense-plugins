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
    },
    servers: [
      { url: process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3000}` },
    ],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: [routesGlob1, routesGlob2],
};
