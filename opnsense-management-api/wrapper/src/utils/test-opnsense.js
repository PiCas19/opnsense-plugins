// scripts/test-opnsense.js
const { getEnv } = require('./env');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');

async function testOPNsenseConnection() {
  console.log('Testing OPNsense Connection');
  console.log('===============================');

  // Config da ENV
  const host = getEnv('OPNSENSE_HOST');
  const apiKey = getEnv('OPNSENSE_API_KEY');
  const apiSecret = getEnv('OPNSENSE_API_SECRET');
  const verifySSL = getEnv('OPNSENSE_VERIFY_SSL', 'false') === 'true';
  const caFileRaw = getEnv('OPNSENSE_CA_FILE'); // opzionale quando verifySSL=true

  // Disattiva verifica TLS globalmente se richiesto (nessun https.Agent)
  if (!verifySSL) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  // CA opzionale quando verifySSL=true
  let httpsAgent = undefined;
  if (verifySSL) {
    const caFile = caFileRaw
      ? (path.isAbsolute(caFileRaw) ? caFileRaw : path.resolve(process.cwd(), caFileRaw))
      : null;
    let caPem;
    if (caFile) {
      try {
        caPem = fs.readFileSync(caFile);
        console.log(`Using CA file: ${caFile} (${caPem.length} bytes)`);
      } catch (e) {
        console.warn(`⚠️  Could not read CA file '${caFile}': ${e.message}`);
      }
    }
    httpsAgent = new https.Agent({
      rejectUnauthorized: true,
      ca: caPem,
      keepAlive: true,
      timeout: 5000
    });
  }

  // Log configurazione
  console.log('Configuration:');
  console.log(`   Host: ${host || 'NOT SET'}`);
  console.log(`   API Key: ${apiKey ? `${apiKey.substring(0, 8)}...` : 'NOT SET'}`);
  console.log(`   API Secret: ${apiSecret ? `${apiSecret.substring(0, 8)}...` : 'NOT SET'}`);
  console.log(`   SSL Verify: ${verifySSL}`);
  if (!verifySSL) console.log('   TLS verification is DISABLED (NODE_TLS_REJECT_UNAUTHORIZED=0)');

  if (!host || !apiKey || !apiSecret) {
    console.log('Missing required configuration\n');
    console.log('Add to your .env file:');
    console.log('OPNSENSE_HOST=https://your-opnsense-host');
    console.log('OPNSENSE_API_KEY=your_api_key');
    console.log('OPNSENSE_API_SECRET=your_api_secret');
    console.log('OPNSENSE_VERIFY_SSL=false');
    return;
  }

  console.log('\nTesting basic connectivity...');

  try {
    const url = new URL(host);
    console.log(`   Testing: ${url.hostname}:${url.port || (url.protocol === 'https:' ? 443 : 80)}`);

    // Client axios (nessun agent se verifySSL=false)
    const client = axios.create({
      baseURL: host,
      httpsAgent, // solo quando verifySSL=true
      timeout: 15000,
      auth: { username: apiKey, password: apiSecret },
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      validateStatus: s => s >= 200 && s < 400
    });

    // Test 1: pagina base
    console.log('\nTest 1: Basic HTTPS connection...');
    try {
      const response = await client.get('/', { timeout: 5000 });
      console.log(`HTTPS connection successful (Status: ${response.status})`);
    } catch (error) {
      console.log(`HTTPS connection failed: ${error.message}`);
      if (error.code) console.log(`   Error code: ${error.code}`);
      if (error.response?.status) console.log(`   HTTP status: ${error.response.status}`);
    }

    // Test 2: endpoint semplici
    console.log('\nTest 2: API authentication...');
    const testEndpoints = [
      '/api/core/firmware/status',
      '/api/diagnostics/interface/getInterfaceConfig'
    ];

    for (const endpoint of testEndpoints) {
      try {
        console.log(`   Testing: ${endpoint}`);
        const response = await client.get(endpoint, { timeout: 5000 });
        console.log(`${endpoint} -> Status: ${response.status}`);
        if (response.data) {
          const keys = Object.keys(response.data);
          console.log(`   Response keys: ${keys.slice(0, 5).join(', ')}${keys.length > 5 ? '...' : ''}`);
        }
        break;
      } catch (error) {
        console.log(`   ${endpoint} -> ${error.message}`);
        if (error.response?.status) {
          console.log(`      HTTP Status: ${error.response.status}`);
          if (error.response?.data) {
            console.log(`      Response: ${JSON.stringify(error.response.data).substring(0, 200)}`);
          }
          if (error.response.status === 403) {
            console.log('      ➜ Forbidden: manca il privilegio RBAC per questo endpoint.');
          } else if (error.response.status === 401) {
            console.log('      ➜ Unauthorized: API key/secret errati o utente disabilitato.');
          }
        }
      }
    }

    // Test 3: Firewall API (usa POST con JSON)
    console.log('\n🔍 Test 3: Firewall API...');
    try {
      const response = await client.post(
        '/api/firewall/filter/searchRule',
        {
          current: 1,
          rowCount: 5,
          sort: {},
          searchPhrase: ''
        },
        { timeout: 7000 }
      );
      console.log(`Firewall API accessible (Status: ${response.status})`);
      if (response.data?.rows) {
        console.log(`   Found ${response.data.rows.length} firewall rules`);
      } else {
        console.log('   No rows field in response.');
      }
    } catch (error) {
      console.log(`Firewall API failed: ${error.message}`);
      if (error.response?.status) {
        console.log(`   HTTP Status: ${error.response.status}`);
        if (error.response?.data) {
          console.log(`   Response: ${JSON.stringify(error.response.data).substring(0, 300)}`);
        }
        if (error.response.status === 403) {
          console.log('   ➜ Permessi: assegna all’utente API i privilegi Firewall: Rules (view).');
        } else if (error.response.status === 400) {
          console.log('   ➜ 400 Invalid JSON: controlla che il body sia JSON e non form-data.');
        }
      }
    }

    // Test 4: Apply config
    console.log('\nTest 4: Configuration apply...');
    try {
      const response = await client.post('/api/firewall/filter/apply', {}, { timeout: 10000 });
      console.log(`Apply config successful (Status: ${response.status})`);
    } catch (error) {
      console.log(`Apply config failed: ${error.message}`);
      if (error.response?.status) {
        console.log(`   HTTP Status: ${error.response.status}`);
        if (error.response.status === 403) {
          console.log('   ➜ Permessi: serve privilegio "Apply configuration" per Firewall/Filter.');
        }
      }
    }
  } catch (error) {
    console.log(`Connection test failed: ${error.message}`);
    console.log('\nTroubleshooting tips:');
    console.log('1) Se usi SSL off (VERIFY=false) stai usando NODE_TLS_REJECT_UNAUTHORIZED=0.');
    console.log('2) Per 403 assegna all’utente API i privilegi RBAC corretti o usa Full Administrator.');
    console.log('3) Verifica che gli endpoint POST abbiano body JSON valido.');
  }

  console.log('\nSummary:');
  console.log('If tests fail, the service will automatically use mock mode');
  console.log('This allows development without a real OPNsense instance');
}

if (require.main === module) {
  testOPNsenseConnection()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Test failed:', error);
      process.exit(1);
    });
}

module.exports = { testOPNsenseConnection };
