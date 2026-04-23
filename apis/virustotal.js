// ============================================================
//  apis/virustotal.js  —  VirusTotal URL scanner
//  Docs: https://developers.virustotal.com/reference/scan-url
// ============================================================

const axios    = require('axios');
const { apis } = require('../config');

class VtRateLimitError extends Error {
  constructor(msg) { super(msg); this.name = 'VtRateLimitError'; }
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── VT request queue ──────────────────────────────────────────
// VT public API: 4 req/min. Queue serialises calls so bursts
// don't all 429 simultaneously. With 0 ms delay we rely on the
// natural async wait between calls; flip VT_DELAY_MS > 0 if you
// hit 429s and want guaranteed spacing.
const VT_DELAY_MS = 0;
let queueTail = Promise.resolve();

function enqueue(fn) {
  return new Promise((resolve, reject) => {
    queueTail = queueTail.then(async () => {
      try   { resolve(await fn()); }
      catch (err) { reject(err); }
      if (VT_DELAY_MS > 0) await sleep(VT_DELAY_MS);
    }).catch(err => console.error('[virustotal] queue tail error:', err));
  });
}

/**
 * Submit URL to VT. Returns the analysis ID.
 */
async function submitUrl(url, headers) {
  const params = new URLSearchParams();
  params.append('url', url);
  try {
    const res = await axios.post('https://www.virustotal.com/api/v3/urls', params.toString(), {
      headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
      timeout: 10000,
    });
    return res.data.data.id;
  } catch (err) {
    if (err.response?.status === 429) throw new VtRateLimitError('VirusTotal Error 429: Quota exceeded.');
    throw err;
  }
}

/**
 * Poll analysis ID with exponential backoff.
 * Sleeps before the first poll so VT has time to start processing.
 * 2 s → 3 s → 4.5 s → ... → 10 s cap. Max ~60 s total.
 */
async function pollAnalysis(analysisId, headers) {
  const maxAttempts = 12;
  let   delay       = 2000;
  const maxDelay    = 10000;

  for (let i = 0; i < maxAttempts; i++) {
    await sleep(delay);
    delay = Math.min(Math.ceil(delay * 1.5), maxDelay);

    const res  = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers, timeout: 10000 });
    const data = res.data.data;
    if (data.attributes.status === 'completed') return data;
    // status 'queued' or 'in-progress' — keep polling
  }
  throw new Error(`VT URL analysis timed out for ${analysisId}`);
}

/**
 * Try to get an existing VT analysis for this URL without submitting a new one.
 * Costs 1 GET. Returns null on 404 (URL never seen by VT).
 */
async function getExistingAnalysis(url, headers) {
  const id = Buffer.from(url).toString('base64url');
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${id}`, { headers, timeout: 10000 });
    return res.data.data;
  } catch (err) {
    if (err.response?.status === 404) return null;
    if (err.response?.status === 429) throw new VtRateLimitError('VirusTotal Error 429: Quota exceeded.');
    throw err;
  }
}

/**
 * Check a URL with VirusTotal.
 * First tries existing reputation (1 quota unit, instant).
 * Falls back to fresh submit + poll only for unknown URLs.
 *
 * @param {string} url
 * @returns {Promise<{ safe: boolean, maliciousCount: number, raw: object }>}
 */
async function checkUrl(url) {
  if (!apis.virustotal.enabled) throw new Error('VIRUSTOTAL_DISABLED');
  const headers = { 'x-apikey': apis.virustotal.apiKey };

  return enqueue(async () => {
    let finalData = await getExistingAnalysis(url, headers);
    if (!finalData) {
      const analysisId = await submitUrl(url, headers);
      finalData = await pollAnalysis(analysisId, headers);
    }
    const stats        = finalData.attributes.last_analysis_stats || finalData.attributes.stats;
    const maliciousCount = stats.malicious || 0;
    return { safe: maliciousCount === 0, maliciousCount, raw: finalData };
  });
}

module.exports = { checkUrl, VtRateLimitError };
