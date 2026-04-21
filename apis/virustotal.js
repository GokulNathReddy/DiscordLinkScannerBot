// ============================================================
//  apis/virustotal.js  —  VirusTotal URL scanner w/ Queuing
//  Docs: https://developers.virustotal.com/reference/scan-url
// ============================================================

const axios = require('axios');
const { apis } = require('../config');

// VT Public API is strictly limited to 4 requests/minute.
// 15000ms delay between POST operations ensures we never exceed this.
const VT_DELAY_MS = 15000;

class VtRateLimitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VtRateLimitError';
  }
}

/** Global promise chain used to enforce the 15s delay. */
let queueTail = Promise.resolve();

/** Pause execution for ms milliseconds */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @typedef {Object} VtResult
 * @property {boolean} safe         - true if malicious count === 0
 * @property {number}  maliciousCount - number of vendors flagging
 * @property {object}  raw          - Full raw VT analysis response
 */

/**
 * Enqueue a function to run strictly after previous queued functions
 * with a mandatory 15s delay to satisfy VT 4/min limits.
 *
 * @param {() => Promise<any>} fn
 * @returns {Promise<any>}
 */
function enqueue(fn) {
  return new Promise((resolve, reject) => {
    queueTail = queueTail
      .then(async () => {
        try {
          const result = await fn();
          resolve(result);
        } catch (err) {
          reject(err);
        }
        // Force the 15s cooldown after the function completes (successfully or not).
        await sleep(VT_DELAY_MS);
      })
      .catch((err) => {
        // Should not happen, errors are caught above
        console.error('[virustotal] queue tail error:', err);
      });
  });
}

/**
 * Step 1: Submit URL to VirusTotal (consumes quota).
 * Returns the `id` needed to fetch the analysis.
 *
 * @param {string} url
 * @param {object} headers
 * @returns {Promise<string>}
 */
async function submitUrl(url, headers) {
  // Use URLSearchParams as VT requires standard form-urlencoded for the url field.
  const params = new URLSearchParams();
  params.append('url', url);

  try {
    const res = await axios.post('https://www.virustotal.com/api/v3/urls', params.toString(), {
      headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
      timeout: 10000,
    });
    return res.data.data.id;
  } catch (error) {
    if (error.response?.status === 429) {
      throw new VtRateLimitError('VirusTotal Error 429: Quota exceeded.');
    }
    throw error;
  }
}

/**
 * Step 2: Poll analysis ID until status is 'completed'.
 *
 * @param {string} analysisId
 * @param {object} headers
 * @returns {Promise<any>}
 */
async function pollAnalysis(analysisId, headers) {
  const maxAttempts = 12; // 12 * 5s = 60s max polling
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const res = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers,
      timeout: 10000,
    });

    const data = res.data.data;
    if (data.attributes.status === 'completed') {
      return data;
    }
    if (data.attributes.status === 'queued') {
      // Still queued on their end, wait a bit
      await sleep(5000);
      continue;
    }
  }
  throw new Error(`Analysis timed out for ${analysisId}`);
}

/**
 * Check a URL using VirusTotal.
 * Queues the request automatically. Throws VtRateLimitError on 429.
 *
 * @param {string} url
 * @returns {Promise<VtResult>}
 */
async function checkUrl(url) {
  if (!apis.virustotal.enabled) {
    throw new Error('VIRUSTOTAL_DISABLED');
  }

  const headers = { 'x-apikey': apis.virustotal.apiKey };

  // Core execution step (queued to enforce rate limit)
  const execute = async () => {
    // 1. Submit
    const analysisId = await submitUrl(url, headers);
    // 2. Poll
    const finalData = await pollAnalysis(analysisId, headers);
    
    const stats = finalData.attributes.stats;
    const maliciousCount = stats.malicious || 0;
    const safe = maliciousCount === 0;

    return { safe, maliciousCount, raw: finalData };
  };

  return await enqueue(execute);
}

module.exports = { checkUrl, VtRateLimitError };
