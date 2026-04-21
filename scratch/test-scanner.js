const { scanPipeline } = require('../utils/scanner');

async function testPipeline() {
  console.log('Testing GitHub...');
  const res1 = await scanPipeline('https://github.com/');
  console.log(res1);
}

testPipeline();
