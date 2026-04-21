// ============================================================
//  utils/scanner.js  —  Combined scanning pipeline
//  SDP → (IPQS || VT) parallel fallback logic
// ============================================================

const stopPhishing = require('stop-discord-phishing');
const { EmbedBuilder } = require('discord.js');
const { checkUrl: checkIpqs } = require('../apis/ipqualityscore');
const { checkUrl: checkVt, VtRateLimitError } = require('../apis/virustotal');
const cache = require('./cache');
const { config } = require('../config'); // used for checking enablement in lower levels but we can check here too.

/**
 * @typedef {Object} ScanResult
 * @property {boolean} safe          - True if passed all checks
 * @property {string|null} reason    - 'stop-discord-phishing', 'ipqs', or 'virustotal' if failed
 * @property {string|null} note      - Optional context like "VirusTotal Unavailable"
 * @property {number|null} ipqsScore - The IPQS risk score (if available)
 * @property {number|null} vtMalicious - The VT malicious count (if available)
 * @property {string|null} apiErrorContext - String detailing which APIs failed if any
 */

/**
 * Run a URL through the full security pipeline.
 *
 * 1. stop-discord-phishing (Local, Instant)
 *    ↓ passes?
 * 2. Cache hit?
 *    ↓ misses?
 * 3. Promise.all( IPQS, VirusTotal )
 *
 * @param {string} url
 * @returns {Promise<ScanResult>}
 */
async function scanPipeline(url) {
  // --- 1. LOCAL CHECK (stop-discord-phishing) ---
  // Using true for strict mode checking both phishing and suspicious.
  const isSpam = await stopPhishing.checkMessage(url, true);
  if (isSpam) {
    return {
      safe: false,
      reason: 'stop-discord-phishing',
      note: null,
      ipqsScore: null,
      vtMalicious: null,
      apiErrorContext: null
    };
  }

  // --- 2. CACHE ---
  const cached = cache.get(url);
  if (cached) return cached;

  // --- 3. Parallel API Execution (IPQS + VT) ---
  let ipqsPromise = checkIpqs(url).catch(e => e); // catch so Promise.all doesn't fail fast
  let vtPromise   = checkVt(url).catch(e => e);

  const [ipqsRes, vtRes] = await Promise.all([ipqsPromise, vtPromise]);

  const ipqsSuccess = !(ipqsRes instanceof Error);
  const vtSuccess   = !(vtRes instanceof Error);

  const resultTemplate = {
    safe: true,
    reason: null,
    note: null,
    ipqsScore: ipqsSuccess ? ipqsRes.riskScore : null,
    vtMalicious: vtSuccess ? vtRes.maliciousCount : null,
    apiErrorContext: null
  };

  // Scenario A: Both failed!
  if (!ipqsSuccess && !vtSuccess) {
    const errorMsg = `Both IPQS and VirusTotal failed. IPQS: ${ipqsRes.message} | VT: ${vtRes.message}`;
    console.error(`[scanner] Both failed for ${url}:`, errorMsg);
    resultTemplate.safe = false;
    resultTemplate.reason = 'API_FAILURE_BOTH';
    resultTemplate.note = 'Both APIs down or rate limited.';
    resultTemplate.apiErrorContext = 'VirusTotal, IPQualityScore';
    return resultTemplate; // Don't cache complete failures.
  }

  // Scenario B: One failed
  if (!ipqsSuccess) {
    console.warn(`[scanner] IPQS failed for ${url}:`, ipqsRes.message);
    resultTemplate.apiErrorContext = 'IPQualityScore';
    resultTemplate.note = 'IPQualityScore unavailable — VirusTotal only.';
  }
  if (!vtSuccess) {
    console.warn(`[scanner] VT failed for ${url}:`, vtRes.message);
    resultTemplate.apiErrorContext = 'VirusTotal';
    // If it was a 429 rate limit, make it explicit.
    if (vtRes instanceof VtRateLimitError) {
      resultTemplate.note = 'VirusTotal unavailable (Rate Limited) — IPQualityScore only.';
    } else {
      resultTemplate.note = 'VirusTotal unavailable — IPQualityScore only.';
    }
  }

  // Final evaluation logic
  // Assume safe initially. If ANY successful API flagged it, mark malicious.
  resultTemplate.safe = true; 

  if (ipqsSuccess && !ipqsRes.safe) {
    resultTemplate.safe = false;
    resultTemplate.reason = 'IPQualityScore';
  } else if (vtSuccess && !vtRes.safe) {
    resultTemplate.safe = false;
    resultTemplate.reason = 'VirusTotal';
  }

  // Only cache if the URL is resolved securely (i.e. we got a definitive answer).
  // Don't cache API errors. We consider partial failures (one API) cacheable.
  cache.set(url, resultTemplate);
  return resultTemplate;
}

module.exports = { scanPipeline };
