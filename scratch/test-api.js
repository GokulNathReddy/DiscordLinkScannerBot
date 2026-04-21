const axios = require('axios');

const ipqsKey = 'vZyJDcxyg7aJJEVab7kAsQcxPWzEoisK';
const vtKey = '695a69a7112cf6dbef1bca1d79552dba501a133b65f63cc407b18c6f5b747d06';
const testUrl = 'https://github.com/';

async function testIpqs() {
  const encoded = encodeURIComponent(testUrl);
  try {
    const res = await axios.get(`https://www.ipqualityscore.com/api/json/url/${ipqsKey}/${encoded}?strictness=1&fast=1`);
    console.log('IPQS Result:', res.data);
  } catch (e) {
    console.log('IPQS Error:', e.response?.data || e.message);
  }
}

async function testVt() {
  try {
    const params = new URLSearchParams();
    params.append('url', testUrl);
    const res = await axios.post('https://www.virustotal.com/api/v3/urls', params.toString(), {
      headers: { 'x-apikey': vtKey, 'content-type': 'application/x-www-form-urlencoded' }
    });
    console.log('VT Submit Result:', res.data);
  } catch (e) {
    console.log('VT Error:', e.response?.data || e.message);
  }
}

testIpqs();
testVt();
