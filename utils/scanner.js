// ============================================================
//  utils/scanner.js  —  Combined URL scanning pipeline
//  SDP (local) → cache → liveness + IPQS + VT (all parallel)
// ============================================================

const stopPhishing              = require('stop-discord-phishing');
const axios                     = require('axios');
const { checkUrl: checkIpqs }   = require('../apis/ipqualityscore');
const { checkUrl: checkVt, VtRateLimitError } = require('../apis/virustotal');
const cache                     = require('./cache');

/**
 * Run a URL through the full security pipeline.
 *
 *  1. stop-discord-phishing   (local, instant, free)
 *  2. URL cache hit?          (local, instant, free)
 *  3. Liveness + IPQS + VT   (all three fire in parallel — no sequential wait)
 *
 * @param {string} url
 * @param {Function} updateStatus
 * @returns {Promise<ScanResult>}
 */
async function scanPipeline(url, updateStatus = () => {}) {

  // ── 1. Local phishing blocklist (instant) ──────────────────
  updateStatus('Cross-referencing phishing blocklists...');
  const isSpam = await stopPhishing.checkMessage(url, true);
  if (isSpam) {
    return { safe: false, reason: 'stop-discord-phishing', note: null, ipqsScore: null, vtMalicious: null, apiErrorContext: null };
  }

  // ── 2. Cache lookup ────────────────────────────────────────
  const cached = cache.get(url);
  if (cached) {
    updateStatus('Cache hit — retrieving prior scan results...');
    return cached;
  }

  // ── 3. Liveness check + IPQS + VT — all in parallel ───────
  // Firing all three together means a slow liveness check never delays
  // the API responses, and a fast liveness failure short-circuits cheaply.
  updateStatus('Resolving domain & querying threat intelligence engines...');

  const livenessPromise = axios.head(url, {
    timeout: 5000,
    maxRedirects: 3,
    validateStatus: () => true,  // never throw on HTTP status
  }).catch(e => e); // network errors become Error objects

  const ipqsPromise = checkIpqs(url).catch(e => e);
  const vtPromise   = checkVt(url).catch(e => e);

  // Live status feedback as each API comes back (fire-and-forget)
  ipqsPromise.then(r => { if (!(r instanceof Error)) updateStatus('IPQualityScore responded — awaiting VirusTotal...'); }).catch(() => {});
  vtPromise.then(r   => { if (!(r instanceof Error)) updateStatus('VirusTotal responded — analysing threat report...'); }).catch(() => {});

  const [livenessRes, ipqsRes, vtRes] = await Promise.all([livenessPromise, ipqsPromise, vtPromise]);

  // ── Evaluate liveness ─────────────────────────────────────
  if (livenessRes instanceof Error) {
    return { safe: false, reason: 'Invalid or Unreachable Domain', note: null, ipqsScore: null, vtMalicious: null, apiErrorContext: null };
  }
  if (livenessRes.status === 404) {
    return { safe: false, reason: 'Dead Link (404 Not Found)', note: null, ipqsScore: null, vtMalicious: null, apiErrorContext: null };
  }

  // ── Evaluate API results ──────────────────────────────────
  updateStatus('Compiling threat intelligence report...');

  const ipqsSuccess = !(ipqsRes instanceof Error);
  const vtSuccess   = !(vtRes   instanceof Error);

  const result = {
    safe: true,
    reason: null,
    note: null,
    ipqsScore:      ipqsSuccess ? ipqsRes.riskScore      : null,
    vtMalicious:    vtSuccess   ? vtRes.maliciousCount   : null,
    apiErrorContext: null,
  };

  // Both APIs failed — block for safety, do not cache
  if (!ipqsSuccess && !vtSuccess) {
    console.error(`[scanner] Both APIs failed for ${url}: IPQS=${ipqsRes.message} | VT=${vtRes.message}`);
    return { ...result, safe: false, reason: 'API_FAILURE_BOTH', note: 'Both APIs down or rate limited.', apiErrorContext: 'VirusTotal, IPQualityScore' };
  }

  if (!ipqsSuccess) {
    console.warn(`[scanner] IPQS failed for ${url}:`, ipqsRes.message);
    result.apiErrorContext = 'IPQualityScore';
    result.note = 'IPQualityScore unavailable — VirusTotal only.';
  }
  if (!vtSuccess) {
    console.warn(`[scanner] VT failed for ${url}:`, vtRes.message);
    result.apiErrorContext = 'VirusTotal';
    result.note = vtRes instanceof VtRateLimitError
      ? 'VirusTotal unavailable (Rate Limited) — IPQualityScore only.'
      : 'VirusTotal unavailable — IPQualityScore only.';
  }

  // Evaluate threat flags from each successful API
  if (ipqsSuccess) {
    if (!ipqsRes.safe) {
      result.safe = false; result.reason = 'IPQualityScore';
    } else if (ipqsRes.raw?.adult === true) {
      result.safe = false; result.reason = 'Adult/NSFW Content';
    }
  }
  if (result.safe && vtSuccess) {
    if (!vtRes.safe) {
      result.safe = false; result.reason = 'VirusTotal';
    } else if (vtRes.raw?.attributes?.categories) {
      const cats = Object.values(vtRes.raw.attributes.categories).join(' ').toLowerCase();
      const adultKw = ['adult','porn','sexually explicit','sex','x-rated','erotica','nsfw'];
      if (adultKw.some(kw => cats.includes(kw))) {
        result.safe = false; result.reason = 'Adult/NSFW Content';
      }
    }
  }

  // Cache definitive results (not API failures)
  cache.set(url, result);
  return result;
}

module.exports = { scanPipeline };
