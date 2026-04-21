const axios = require('axios');
const crypto = require('crypto');

const vtKey = '695a69a7112cf6dbef1bca1d79552dba501a133b65f63cc407b18c6f5b747d06';

function getUrlId(url) {
  // VT requires base64url encoding without padding
  return Buffer.from(url).toString('base64url');
}

async function checkExisting(url) {
  const id = getUrlId(url);
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': vtKey }
    });
    console.log('Categories:', res.data.data.attributes.categories);
  } catch (e) {
    console.log('Error:', e.response?.data || e.message);
  }
}

checkExisting('https://pornhub.com/');
