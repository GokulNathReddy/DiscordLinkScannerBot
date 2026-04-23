// ============================================================
//  utils/fileScanner.js  —  Attachment malware scanning
//  Flow: localHashCache → VT hash lookup → upload & poll
// ============================================================

const axios    = require('axios');
const crypto   = require('crypto');
const FormData = require('form-data');
const { apis } = require('../config');

// Shared hash result cache (imported from cache.js)
const { hashCache } = require('./cache');

// ── File type classification ──────────────────────────────────
const SKIP_MIME_PREFIXES = ['image/', 'video/', 'audio/'];
const SKIP_EXTENSIONS = new Set([
  'jpg','jpeg','png','gif','webp','svg','bmp','ico','tiff','avif','heic','heif','raw','cr2','nef',
  'mp4','mkv','mov','avi','webm','flv','wmv','m4v','3gp','ts','mts','m2ts',
  'mp3','wav','ogg','flac','aac','m4a','opus','wma','aiff','mid','midi',
]);

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * Classify an attachment: 'scan' or 'skip'.
 * @param {import('discord.js').Attachment} attachment
 * @returns {{ action: 'scan'|'skip', ext: string }}
 */
function classifyAttachment(attachment) {
  const name = (attachment.name || '').toLowerCase();
  const ext  = name.includes('.') ? name.split('.').pop() : '';
  const mime = (attachment.contentType || '').toLowerCase();
  if (SKIP_MIME_PREFIXES.some(p => mime.startsWith(p))) return { action: 'skip', ext };
  if (SKIP_EXTENSIONS.has(ext))                          return { action: 'skip', ext };
  return { action: 'scan', ext: ext || 'unknown' };
}

/**
 * Download attachment bytes and compute SHA-256 hash.
 * @param {string} url
 * @returns {Promise<{ buffer: Buffer, hash: string }>}
 */
async function downloadAndHash(url) {
  const res = await axios.get(url, {
    responseType: 'arraybuffer',
    timeout: 30000,
    maxContentLength: 32 * 1024 * 1024,
  });
  const buffer = Buffer.from(res.data);
  const hash   = crypto.createHash('sha256').update(buffer).digest('hex');
  return { buffer, hash };
}

/**
 * Check VT for a known file hash. Returns result or null (404 = unknown).
 */
async function checkHashReputation(sha256, headers) {
  try {
    const res   = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, { headers, timeout: 10000 });
    const attrs = res.data.data.attributes;
    const stats = attrs.last_analysis_stats;
    const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);
    return {
      safe: maliciousCount === 0,
      maliciousCount,
      suspiciousCount:  stats.suspicious  || 0,
      harmlessCount:    stats.harmless    || 0,
      undetectedCount:  stats.undetected  || 0,
      method: 'hash-lookup',
      ...extractThreatDetails(attrs),
      raw: res.data.data,
    };
  } catch (err) {
    if (err.response?.status === 404) return null;
    if (err.response?.status === 429) throw new Error('VT_RATE_LIMIT');
    throw err;
  }
}

/**
 * Upload file buffer to VT for full sandbox analysis.
 * @returns {Promise<string>} analysis ID
 */
async function uploadFile(buffer, filename, headers) {
  const form = new FormData();
  form.append('file', buffer, { filename });
  const res = await axios.post('https://www.virustotal.com/api/v3/files', form, {
    headers: { ...headers, ...form.getHeaders() },
    timeout: 60000,
    maxContentLength: 32 * 1024 * 1024,
  });
  if (res.data?.data?.id) return res.data.data.id;
  throw new Error('VT upload returned no analysis ID');
}

/**
 * Extract threat names and types from VT raw attributes.
 */
function extractThreatDetails(attributes) {
  const results    = attributes.last_analysis_results || attributes.results || {};
  const threatNames = new Set();
  const threatTypes = new Set();
  for (const engine of Object.values(results)) {
    if (engine.category === 'malicious' || engine.category === 'suspicious') {
      if (engine.result) threatNames.add(engine.result);
      if (engine.method) threatTypes.add(engine.method);
    }
  }
  const typeTags = attributes.type_tags || attributes.tags || [];
  return {
    threatNames:       [...threatNames].slice(0, 5),
    threatTypes:       [...new Set([...typeTags, ...threatTypes])].slice(0, 5),
    popularThreatName: attributes.popular_threat_classification?.suggested_threat_label || null,
  };
}

/**
 * Poll VT analysis with exponential backoff.
 * Starts at 2 s, grows ×1.5 per attempt, caps at 15 s.
 * Max ~3 min total. Much faster than the original flat 5 s × 60.
 */
async function pollFileAnalysis(analysisId, headers) {
  const maxAttempts = 30;
  let   delay       = 2000;
  const maxDelay    = 15000;

  for (let i = 0; i < maxAttempts; i++) {
    await sleep(delay);
    delay = Math.min(Math.ceil(delay * 1.5), maxDelay);

    const res  = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers, timeout: 10000 });
    const data = res.data.data;
    if (data.attributes.status === 'completed') {
      const stats        = data.attributes.stats;
      const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);
      return {
        safe: maliciousCount === 0,
        maliciousCount,
        suspiciousCount:  stats.suspicious  || 0,
        harmlessCount:    stats.harmless    || 0,
        undetectedCount:  stats.undetected  || 0,
        method: 'full-upload',
        ...extractThreatDetails(data.attributes),
        raw: data,
      };
    }
  }
  throw new Error('VT file analysis timed out');
}

/**
 * Full file scan pipeline.
 *
 * Priority order (fastest → slowest):
 *   1. In-process hash cache  — instant, zero API calls
 *   2. VT hash reputation     — 1 fast GET, no upload
 *   3. Full upload + polling  — slowest, only for unknown files
 *
 * @param {import('discord.js').Attachment} attachment
 * @param {Function} updateStatus
 * @param {{ buffer: Buffer, hash: string }|null} preFetchedData
 */
async function scanFilePipeline(attachment, updateStatus = () => {}, preFetchedData = null) {
  if (!apis.virustotal.enabled || !apis.virustotal.apiKey) {
    throw new Error('VirusTotal not configured');
  }

  const headers = { 'x-apikey': apis.virustotal.apiKey };

  // ── Step 1: get buffer + hash ─────────────────────────────
  let buffer, hash;
  if (preFetchedData) {
    ({ buffer, hash } = preFetchedData);
  } else {
    updateStatus(`Downloading \`${attachment.name}\` for analysis...`);
    try {
      ({ buffer, hash } = await downloadAndHash(attachment.url));
    } catch (err) {
      throw new Error(`Download failed: ${err.message}`);
    }
  }

  // ── Step 2: local hash cache (zero API calls) ─────────────
  const cached = hashCache.get(hash);
  if (cached) {
    updateStatus('Known file — returning cached scan result...');
    return cached;
  }

  // ── Step 3: VT hash reputation (1 GET, instant) ───────────
  updateStatus('Checking file signature against VirusTotal database...');
  let result = null;
  try {
    result = await checkHashReputation(hash, headers);
  } catch (err) {
    if (err.message !== 'VT_RATE_LIMIT') console.warn('[fileScanner] hash check failed:', err.message);
  }

  if (result) {
    updateStatus('Hash match found — compiling threat report...');
    hashCache.set(hash, result);
    return result;
  }

  // ── Step 4: full upload + poll ────────────────────────────
  updateStatus('Unknown file — uploading to VirusTotal sandbox...');
  let analysisId;
  try {
    analysisId = await uploadFile(buffer, attachment.name, headers);
  } catch (err) {
    throw new Error(`Upload failed: ${err.message}`);
  }

  updateStatus('File submitted — waiting for 70+ AV engines to analyse...');
  const finalResult = await pollFileAnalysis(analysisId, headers);
  updateStatus('Analysis complete — compiling threat report...');
  hashCache.set(hash, finalResult);
  return finalResult;
}

module.exports = { classifyAttachment, scanFilePipeline, downloadAndHash };
