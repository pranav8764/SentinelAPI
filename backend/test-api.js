import http from 'http';

console.log('Testing backend API...\n');

// Test 1: Root endpoint
const testRoot = () => {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3001,
      path: '/',
      method: 'GET',
      timeout: 5000
    };

    console.log('Test 1: GET /');
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        console.log(`Status: ${res.statusCode}`);
        console.log(`Response: ${data}\n`);
        resolve(true);
      });
    });

    req.on('error', (error) => {
      console.log(`Error: ${error.message}\n`);
      reject(error);
    });

    req.on('timeout', () => {
      console.log('Request timed out\n');
      req.destroy();
      reject(new Error('Timeout'));
    });

    req.end();
  });
};

// Test 2: Health endpoint
const testHealth = () => {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3001,
      path: '/health',
      method: 'GET',
      timeout: 5000
    };

    console.log('Test 2: GET /health');
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        console.log(`Status: ${res.statusCode}`);
        console.log(`Response: ${data}\n`);
        resolve(true);
      });
    });

    req.on('error', (error) => {
      console.log(`Error: ${error.message}\n`);
      reject(error);
    });

    req.on('timeout', () => {
      console.log('Request timed out\n');
      req.destroy();
      reject(new Error('Timeout'));
    });

    req.end();
  });
};

// Run tests
(async () => {
  try {
    await testRoot();
    await testHealth();
    console.log('✅ All tests completed!');
  } catch (error) {
    console.log('❌ Tests failed:', error.message);
  }
})();
