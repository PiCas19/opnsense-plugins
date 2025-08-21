// scripts/test-opnsense.js
const { getEnv } = require('./env');
const axios = require('axios');
const https = require('https');

async function testOPNsenseConnection() {
  console.log('Testing OPNsense Connection');
  console.log('===============================');

  // Leggi configurazione
  const host = getEnv('OPNSENSE_HOST');
  const apiKey = getEnv('OPNSENSE_API_KEY');
  const apiSecret = getEnv('OPNSENSE_API_SECRET');
  const verifySSL = getEnv('OPNSENSE_VERIFY_SSL', 'false') === 'true';

  console.log('Configuration:');
  console.log(`   Host: ${host || 'NOT SET'}`);
  console.log(`   API Key: ${apiKey ? `${apiKey.substring(0, 8)}...` : 'NOT SET'}`);
  console.log(`   API Secret: ${apiSecret ? `${apiSecret.substring(0, 8)}...` : 'NOT SET'}`);
  console.log(`   SSL Verify: ${verifySSL}`);

  if (!host || !apiKey || !apiSecret) {
    console.log('Missing required configuration');
    console.log('');
    console.log('Add to your .env file:');
    console.log('OPNSENSE_HOST=https://your-opnsense-ip');
    console.log('OPNSENSE_API_KEY=your_api_key');
    console.log('OPNSENSE_API_SECRET=your_api_secret');
    console.log('OPNSENSE_VERIFY_SSL=false');
    return;
  }

  // Test di base - ping/connessione
  console.log('\nTesting basic connectivity...');
  
  try {
    const url = new URL(host);
    console.log(`   Testing: ${url.hostname}:${url.port || (url.protocol === 'https:' ? 443 : 80)}`);
    
    // Test connessione TCP di base
    const httpsAgent = new https.Agent({
      rejectUnauthorized: verifySSL,
      timeout: 5000
    });

    const client = axios.create({
      baseURL: host,
      httpsAgent,
      timeout: 10000,
      auth: {
        username: apiKey,
        password: apiSecret
      },
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    // Test 1: Status page (non-API)
    console.log('\nTest 1: Basic HTTPS connection...');
    try {
      const response = await client.get('/', { timeout: 5000 });
      console.log(`HTTPS connection successful (Status: ${response.status})`);
    } catch (error) {
      console.log(`HTTPS connection failed: ${error.message}`);
      if (error.code) console.log(`   Error code: ${error.code}`);
      if (error.response?.status) console.log(`   HTTP status: ${error.response.status}`);
    }

    // Test 2: API endpoint semplice
    console.log('\nTest 2: API authentication...');
    const testEndpoints = [
      '/api/core/firmware/status',
      '/api/diagnostics/interface/getInterfaceConfig', 
      '/api/firewall/filter/searchRule'
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
        break; // Se uno funziona, interrompi
      } catch (error) {
        console.log(`   ${endpoint} -> ${error.message}`);
        if (error.response?.status) {
          console.log(`      HTTP Status: ${error.response.status}`);
          if (error.response?.data) {
            console.log(`      Response: ${JSON.stringify(error.response.data).substring(0, 200)}`);
          }
        }
      }
    }

    // Test 3: Specifica per firewall rules
    console.log('\n🔍 Test 3: Firewall API...');
    try {
      const response = await client.get('/api/firewall/filter/searchRule', {
        params: { current: 1, rowCount: 5 }
      });
      console.log(`Firewall API accessible (Status: ${response.status})`);
      if (response.data?.rows) {
        console.log(`   Found ${response.data.rows.length} firewall rules`);
      }
    } catch (error) {
      console.log(`Firewall API failed: ${error.message}`);
      if (error.response?.status === 401) {
        console.log('   This looks like an authentication issue');
        console.log('   Check your API key and secret');
      } else if (error.response?.status === 403) {
        console.log('   Access forbidden - check API permissions in OPNsense');
      }
    }

    console.log('\nTest 4: Configuration apply...');
    try {
      const response = await client.post('/api/firewall/filter/apply');
      console.log(`Apply config successful (Status: ${response.status})`);
    } catch (error) {
      console.log(`Apply config failed: ${error.message}`);
      if (error.response?.status) {
        console.log(`   HTTP Status: ${error.response.status}`);
      }
    }

  } catch (error) {
    console.log(`Connection test failed: ${error.message}`);
    console.log('\nTroubleshooting tips:');
    console.log('1. Check if OPNsense is running and accessible');
    console.log('2. Verify the IP address/hostname');
    console.log('3. Check firewall rules blocking API access');
    console.log('4. Ensure API is enabled in OPNsense System -> Access -> Users');
    console.log('5. Verify API key and secret are correct');
  }

  console.log('\nSummary:');
  console.log('If tests fail, the service will automatically use mock mode');
  console.log('This allows development without a real OPNsense instance');
}

if (require.main === module) {
  testOPNsenseConnection().then(() => {
    process.exit(0);
  }).catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
  });
}

module.exports = { testOPNsenseConnection };