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

const delay = (ms) => new Promise(r => setTimeout(r, ms));

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
async function scanPipeline(url, onProgress) {
  // --- 1. LOCAL CHECK (stop-discord-phishing) ---
  if (onProgress) {
    await onProgress('*Checking local databases...*');
    await delay(800); // Visual delay for effect
  }
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
  if (cached) {
    if (onProgress) {
      await onProgress('*Loaded result from secure cache...*');
      await delay(600);
    }
    return cached;
  }

  // --- 2.5 LIVENESS / DEAD LINK CHECK ---
  // The user explicitly requested to kill 404s and invalid links.
  if (onProgress) {
    await onProgress('*Verifying link liveness...*');
    await delay(600);
  }
  try {
    const axios = require('axios');
    const res = await axios.head(url, { 
      timeout: 5000, 
      maxRedirects: 3,
      validateStatus: () => true // Don't throw on status codes
    });
    
    // We only explicitly execute on absolute dead signatures (404 Not Found)
    // We ignore Cloudflare 403s, 503s etc., because they mean the domain exists.
    if (res.status === 404) {
      return {
        safe: false,
        reason: 'Dead Link (404 Not Found)',
        note: null,
        ipqsScore: null,
        vtMalicious: null,
        apiErrorContext: null
      };
    }
  } catch (err) {
    // Network errors like ENOTFOUND (fake domain), ECONNREFUSED, or timeouts
    return {
      safe: false,
      reason: 'Invalid or Unreachable Domain',
      note: null,
      ipqsScore: null,
      vtMalicious: null,
      apiErrorContext: null
    };
  }

  // --- 3. Parallel API Execution (IPQS + VT) ---
  if (onProgress) {
    await onProgress('*Starting VirusTotal & IPQualityScore analysis...*');
    await delay(800);
  }
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

  if (ipqsSuccess) {
    if (!ipqsRes.safe) {
      resultTemplate.safe = false;
      resultTemplate.reason = 'IPQualityScore';
    } else if (ipqsRes.raw && ipqsRes.raw.adult === true) {
      resultTemplate.safe = false;
      resultTemplate.reason = 'Adult/NSFW Content';
    }
  } 
  
  if (resultTemplate.safe && vtSuccess) {
    if (!vtRes.safe) {
      resultTemplate.safe = false;
      resultTemplate.reason = 'VirusTotal';
    } else if (vtRes.raw && vtRes.raw.attributes && vtRes.raw.attributes.categories) {
      // Extract all category values from VT's massive dataset
      const categoriesStr = Object.values(vtRes.raw.attributes.categories).join(' ').toLowerCase();
      const adultKeywords = ['adult', 'porn', 'sexually explicit', 'sex', 'x-rated', 'erotica', 'nsfw'];
      
      const isAdult = adultKeywords.some(kw => categoriesStr.includes(kw));
      if (isAdult) {
        resultTemplate.safe = false;
        resultTemplate.reason = 'Adult/NSFW Content';
      }
    }
  }

  // Only cache if the URL is resolved securely (i.e. we got a definitive answer).
  // Don't cache API errors. We consider partial failures (one API) cacheable.
  cache.set(url, resultTemplate);
  return resultTemplate;
}

module.exports = { scanPipeline };
