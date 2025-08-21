const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Swagger definition
const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'OPNsense Firewall API',
    version: '1.0.0',
    description: 'API REST per la gestione delle regole firewall di OPNsense con autenticazione JWT',
    contact: {
      name: 'API Support',
      email: 'support@example.com'
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT'
    }
  },
  servers: [
    {
      url: process.env.API_BASE_URL || 'http://localhost:3000',
      description: 'Development server'
    },
    {
      url: 'https://api.yourdomain.com',
      description: 'Production server'
    }
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT token per autenticazione'
      }
    },
    schemas: {
      // Schema User
      User: {
        type: 'object',
        properties: {
          id: {
            type: 'integer',
            description: 'ID utente'
          },
          username: {
            type: 'string',
            description: 'Nome utente',
            example: 'admin'
          },
          email: {
            type: 'string',
            format: 'email',
            description: 'Email utente',
            example: 'admin@example.com'
          },
          first_name: {
            type: 'string',
            description: 'Nome',
            example: 'Mario'
          },
          last_name: {
            type: 'string',
            description: 'Cognome',
            example: 'Rossi'
          },
          role: {
            type: 'string',
            enum: ['admin', 'operator', 'viewer'],
            description: 'Ruolo utente'
          },
          is_active: {
            type: 'boolean',
            description: 'Utente attivo'
          },
          last_login: {
            type: 'string',
            format: 'date-time',
            description: 'Ultimo accesso'
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Data creazione'
          },
          updated_at: {
            type: 'string',
            format: 'date-time',
            description: 'Data aggiornamento'
          }
        }
      },

      // Schema Rule
      Rule: {
        type: 'object',
        properties: {
          id: {
            type: 'integer',
            description: 'ID regola'
          },
          uuid: {
            type: 'string',
            format: 'uuid',
            description: 'UUID regola'
          },
          description: {
            type: 'string',
            description: 'Descrizione regola',
            example: 'Block malicious IPs'
          },
          interface: {
            type: 'string',
            enum: ['wan', 'lan', 'dmz', 'opt1', 'opt2', 'opt3', 'opt4'],
            description: 'Interfaccia di rete'
          },
          direction: {
            type: 'string',
            enum: ['in', 'out'],
            description: 'Direzione traffico'
          },
          action: {
            type: 'string',
            enum: ['pass', 'block', 'reject'],
            description: 'Azione da intraprendere'
          },
          protocol: {
            type: 'string',
            enum: ['tcp', 'udp', 'icmp', 'any'],
            description: 'Protocollo'
          },
          source_config: {
            type: 'object',
            description: 'Configurazione sorgente',
            properties: {
              type: {
                type: 'string',
                enum: ['any', 'single', 'network']
              },
              address: {
                type: 'string',
                description: 'Indirizzo IP (per type=single)'
              },
              network: {
                type: 'string',
                description: 'Rete CIDR (per type=network)'
              },
              port: {
                type: 'integer',
                minimum: 1,
                maximum: 65535,
                description: 'Porta'
              }
            }
          },
          destination_config: {
            type: 'object',
            description: 'Configurazione destinazione',
            properties: {
              type: {
                type: 'string',
                enum: ['any', 'single', 'network']
              },
              address: {
                type: 'string',
                description: 'Indirizzo IP (per type=single)'
              },
              network: {
                type: 'string',
                description: 'Rete CIDR (per type=network)'
              },
              port: {
                type: 'integer',
                minimum: 1,
                maximum: 65535,
                description: 'Porta'
              }
            }
          },
          enabled: {
            type: 'boolean',
            description: 'Regola abilitata'
          },
          sequence: {
            type: 'integer',
            description: 'Sequenza/priorità regola'
          },
          log_enabled: {
            type: 'boolean',
            description: 'Logging abilitato'
          },
          created_at: {
            type: 'string',
            format: 'date-time',
            description: 'Data creazione'
          },
          updated_at: {
            type: 'string',
            format: 'date-time',
            description: 'Data aggiornamento'
          }
        }
      },

      // Schema Login
      LoginRequest: {
        type: 'object',
        required: ['username', 'password'],
        properties: {
          username: {
            type: 'string',
            description: 'Nome utente',
            example: 'admin'
          },
          password: {
            type: 'string',
            description: 'Password',
            example: 'Admin123!'
          }
        }
      },

      // Schema Login Response
      LoginResponse: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: true
          },
          message: {
            type: 'string',
            example: 'Login effettuato con successo'
          },
          data: {
            type: 'object',
            properties: {
              accessToken: {
                type: 'string',
                description: 'JWT access token'
              },
              refreshToken: {
                type: 'string',
                description: 'JWT refresh token'
              },
              user: {
                $ref: '#/components/schemas/User'
              }
            }
          }
        }
      },

      // Schema Error
      Error: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: false
          },
          message: {
            type: 'string',
            description: 'Messaggio di errore'
          },
          errors: {
            type: 'array',
            items: {
              type: 'string'
            },
            description: 'Dettagli errori (opzionale)'
          }
        }
      },

      // Schema Success
      Success: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: true
          },
          message: {
            type: 'string',
            description: 'Messaggio di successo'
          },
          data: {
            type: 'object',
            description: 'Dati risposta (opzionale)'
          }
        }
      }
    }
  },
  security: [
    {
      bearerAuth: []
    }
  ]
};

// Options for swagger-jsdoc
const options = {
  definition: swaggerDefinition,
  apis: [
    './src/routes/*.js',
    './src/app.js'
  ]
};

// Generate swagger specification
const swaggerSpec = swaggerJsdoc(options);

// Swagger UI options
const swaggerUiOptions = {
  customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info .title { color: #3b82f6 }
  `,
  customSiteTitle: 'OPNsense Firewall API Documentation',
  customfavIcon: '/favicon.ico',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    docExpansion: 'tag',
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
    tryItOutEnabled: true
  }
};

module.exports = {
  swaggerSpec,
  swaggerUi,
  swaggerUiOptions
};