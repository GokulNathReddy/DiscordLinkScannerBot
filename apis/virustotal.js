// ============================================================
//  apis/virustotal.js  —  VirusTotal URL scanner w/ Queuing
//  Docs: https://developers.virustotal.com/reference/scan-url
// ============================================================

const axios = require('axios');
const { apis } = require('../config');

// VT Public API is strictly limited to 4 requests/minute.
// 0ms delay: we rely on VT Rate Limit Error fallback (IPQS handles load if VT limits)
const VT_DELAY_MS = 0;

class VtRateLimitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VtRateLimitError';
  }
}

/** Global promise chain used to enforce queueing if delay is > 0. */
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
 * Enqueue a function to run strictly after previous queued functions.
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
        if (VT_DELAY_MS > 0) await sleep(VT_DELAY_MS);
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
 * Try to get existing analysis by base64url encoded URL.
 * Costs only 1 request. Returns null if not found (404).
 * @param {string} url
 * @param {object} headers
 */
async function getExistingAnalysis(url, headers) {
  const id = Buffer.from(url).toString('base64url');
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers,
      timeout: 10000,
    });
    return res.data.data;
  } catch (error) {
    if (error.response?.status === 404) return null;
    if (error.response?.status === 429) {
      throw new VtRateLimitError('VirusTotal Error 429: Quota exceeded.');
    }
    throw error;
  }
}

/**
 * Check a URL using VirusTotal.
 * Tries existing reputation first to save quota. Queues the request automatically.
 * Throws VtRateLimitError on 429.
 *
 * @param {string} url
 * @returns {Promise<VtResult>}
 */
async function checkUrl(url) {
  if (!apis.virustotal.enabled) {
    throw new Error('VIRUSTOTAL_DISABLED');
  }

  const headers = { 'x-apikey': apis.virustotal.apiKey };

  const execute = async () => {
    // 1. Try to fetch existing analysis (fast, 1 quota)
    let finalData = await getExistingAnalysis(url, headers);
    
    // 2. If not found, submit new and poll (slow, multiple quota)
    if (!finalData) {
      const analysisId = await submitUrl(url, headers);
      finalData = await pollAnalysis(analysisId, headers);
    }
    
    const stats = finalData.attributes.last_analysis_stats || finalData.attributes.stats;
    const maliciousCount = stats.malicious || 0;
    const safe = maliciousCount === 0;

    return { safe, maliciousCount, raw: finalData };
  };

  return await enqueue(execute);
}

module.exports = { checkUrl, VtRateLimitError };
