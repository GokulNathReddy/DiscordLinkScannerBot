// ============================================================
//  apis/ipqualityscore.js  —  IPQualityScore URL scanner
//  Docs: https://www.ipqualityscore.com/documentation/url-reputation/overview
// ============================================================

const axios = require('axios');
const { apis } = require('../config');

const BASE_URL = 'https://www.ipqualityscore.com/api/json/url';

/**
 * @typedef {Object} IpqsResult
 * @property {boolean} safe         - true if the URL is considered safe
 * @property {boolean} phishing     - IPQS phishing flag
 * @property {boolean} malware      - IPQS malware flag
 * @property {number}  riskScore    - IPQS risk_score (0–100)
 * @property {object}  raw          - Full raw IPQS response
 */

/**
 * Check a URL using IPQualityScore.
 * Throws on network/API errors so scanner.js can handle fallback.
 *
 * @param {string} url
 * @returns {Promise<IpqsResult>}
 */
async function checkUrl(url) {
  if (!apis.ipqs.enabled) {
    throw new Error('IPQS_DISABLED');
  }

  const encoded = encodeURIComponent(url);
  const endpoint = `${BASE_URL}/${apis.ipqs.apiKey}/${encoded}`;

  const response = await axios.get(endpoint, {
    params: {
      strictness:  1,  // 0=lax, 1=medium, 2=strict — medium is a good balance
      fast:        1,  // Return cached result if available for speed
    },
    timeout: 10000,   // 10 second timeout
  });

  const data = response.data;

  // IPQS returns success: false with a message on key problems
  if (!data.success) {
    throw new Error(`IPQS API error: ${data.message || 'Unknown error'}`);
  }

  const phishing  = !!data.phishing;
  const malware   = !!data.malware;
  const riskScore = typeof data.risk_score === 'number' ? data.risk_score : 0;

  const safe = !phishing && !malware && riskScore <= 85;

  return { safe, phishing, malware, riskScore, raw: data };
}

module.exports = { checkUrl };
