// ============================================================
//  utils/fileScanner.js  —  Attachment malware scanning
//  Flow: Hash check (VT) → Upload to VT if unknown
// ============================================================

const axios = require('axios');
const crypto = require('crypto');
const FormData = require('form-data');
const { apis } = require('../config');

// ── File type classification ──────────────────────────────────

// These are safe to pass through — no scanning needed
const SKIP_MIME_PREFIXES = ['image/', 'video/', 'audio/'];
const SKIP_EXTENSIONS = new Set([
  'jpg','jpeg','png','gif','webp','svg','bmp','ico','tiff','avif',
  'mp4','mkv','mov','avi','webm','flv','wmv','m4v',
  'mp3','wav','ogg','flac','aac','m4a','opus',
]);

// These are risky and MUST be scanned
const SCAN_EXTENSIONS = new Set([
  // Executables
  'exe','msi','dll','sys','drv','com','scr','cpl',
  // Scripts
  'bat','cmd','ps1','psm1','psd1','vbs','vbe','js','jse','wsf','wsh','hta',
  'sh','bash','zsh','fish','py','rb','pl','lua','php',
  // Archives (can contain malware)
  'zip','rar','7z','tar','gz','bz2','xz','iso','img','cab',
  // Documents with macro risk
  'pdf','doc','docx','docm','xls','xlsx','xlsm','ppt','pptx','pptm',
  'odt','ods','odp',
  // Code / config
  'html','htm','xml','json','yaml','yml','toml','ini','cfg','conf',
  // Other risky
  'jar','apk','ipa','deb','rpm','dmg','pkg','appimage',
  'lnk','url','torrent','reg','inf',
]);

const VT_DELAY_MS = 15000;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** Global VT queue tail (shared concept with url scanner, separate chain here) */
let fileScanQueueTail = Promise.resolve();

function enqueueFile(fn) {
  return new Promise((resolve, reject) => {
    fileScanQueueTail = fileScanQueueTail
      .then(async () => {
        try {
          resolve(await fn());
        } catch (err) {
          reject(err);
        }
        await sleep(VT_DELAY_MS);
      })
      .catch(err => console.error('[fileScanner] queue error:', err));
  });
}

/**
 * Determine if an attachment should be scanned.
 * Returns 'scan', 'skip', or 'block' (dangerous extension with no scan needed).
 *
 * @param {import('discord.js').Attachment} attachment
 * @returns {{ action: 'scan'|'skip'|'block', ext: string }}
 */
function classifyAttachment(attachment) {
  const name = (attachment.name || '').toLowerCase();
  const ext = name.includes('.') ? name.split('.').pop() : '';
  const mime = (attachment.contentType || '').toLowerCase();

  // Always skip media
  if (SKIP_MIME_PREFIXES.some(p => mime.startsWith(p))) return { action: 'skip', ext };
  if (SKIP_EXTENSIONS.has(ext)) return { action: 'skip', ext };

  // Known risky → scan
  if (SCAN_EXTENSIONS.has(ext)) return { action: 'scan', ext };

  // Unknown extension → scan anyway (safer)
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
    maxContentLength: 32 * 1024 * 1024, // 32MB cap
  });
  const buffer = Buffer.from(res.data);
  const hash = crypto.createHash('sha256').update(buffer).digest('hex');
  return { buffer, hash };
}

/**
 * Check if VT already knows this file hash (fast, 1 quota).
 * Returns result or null if unknown.
 * @param {string} sha256
 * @param {object} headers
 */
async function checkHashReputation(sha256, headers) {
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers,
      timeout: 10000,
    });
    const stats = res.data.data.attributes.last_analysis_stats;
    const maliciousCount = stats.malicious || 0;
    return {
      safe: maliciousCount === 0,
      maliciousCount,
      method: 'hash-lookup',
      raw: res.data.data,
    };
  } catch (err) {
    if (err.response?.status === 404) return null; // Unknown hash, needs full upload
    if (err.response?.status === 429) throw new Error('VT_RATE_LIMIT');
    throw err;
  }
}

/**
 * Upload file buffer to VT for full sandbox analysis.
 * @param {Buffer} buffer
 * @param {string} filename
 * @param {object} headers
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
 * Poll VT analysis until completed.
 * @param {string} analysisId
 * @param {object} headers
 */
async function pollFileAnalysis(analysisId, headers) {
  const maxAttempts = 20; // 20 * 5s = 100s max
  for (let i = 0; i < maxAttempts; i++) {
    const res = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers,
      timeout: 10000,
    });
    const data = res.data.data;
    if (data.attributes.status === 'completed') {
      const stats = data.attributes.stats;
      const maliciousCount = stats.malicious || 0;
      return {
        safe: maliciousCount === 0,
        maliciousCount,
        method: 'full-upload',
        raw: data,
      };
    }
    await sleep(5000);
  }
  throw new Error('VT file analysis timed out');
}

/**
 * Full file scan pipeline.
 * 1. Download + hash
 * 2. Hash reputation check (fast)
 * 3. If unknown → upload & poll
 *
 * @param {import('discord.js').Attachment} attachment
 * @param {Function} updateStatus - async (text: string) => void
 * @returns {Promise<{ safe: boolean, maliciousCount: number, method: string, error?: string }>}
 */
async function scanFilePipeline(attachment, updateStatus = async () => {}) {
  if (!apis.virustotal.enabled || !apis.virustotal.apiKey) {
    throw new Error('VirusTotal not configured');
  }

  const headers = { 'x-apikey': apis.virustotal.apiKey };

  return enqueueFile(async () => {
    // Step 1: Download
    await updateStatus(`Downloading \`${attachment.name}\` for analysis...`);
    let buffer, hash;
    try {
      ({ buffer, hash } = await downloadAndHash(attachment.url));
    } catch (err) {
      throw new Error(`Download failed: ${err.message}`);
    }

    // Step 2: Hash reputation (instant, saves quota)
    await updateStatus(`Checking file signature against VirusTotal database...`);
    let result = null;
    try {
      result = await checkHashReputation(hash, headers);
    } catch (err) {
      if (err.message !== 'VT_RATE_LIMIT') console.warn('[fileScanner] hash check failed:', err.message);
    }

    if (result) {
      await updateStatus(`Hash match found — compiling threat report...`);
      return result;
    }

    // Step 3: Unknown file — upload for full scan
    await updateStatus(`Unknown file — uploading to VirusTotal sandbox...`);
    let analysisId;
    try {
      analysisId = await uploadFile(buffer, attachment.name, headers);
    } catch (err) {
      throw new Error(`Upload failed: ${err.message}`);
    }

    await updateStatus(`File submitted — waiting for 70+ AV engines to analyse...`);
    const finalResult = await pollFileAnalysis(analysisId, headers);
    await updateStatus(`Analysis complete — compiling threat report...`);
    return finalResult;
  });
}

module.exports = { classifyAttachment, scanFilePipeline };
