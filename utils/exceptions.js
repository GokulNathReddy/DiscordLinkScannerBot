// ============================================================
//  utils/exceptions.js  —  Exception list management
//  Reads from disk every call so edits are reflected instantly.
// ============================================================

const fs = require('fs');
const path = require('path');

const ADMIN_FILE = path.join(__dirname, '..', 'adminexceptions.txt');
const USER_FILE  = path.join(__dirname, '..', 'userexceptions.txt');

// ── Helpers ─────────────────────────────────────────────────

/**
 * Load an exception file and return a Set of lowercase domains.
 * @param {string} filePath
 * @returns {Set<string>}
 */
function loadExceptions(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const domains = content
      .split('\n')
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
    return new Set(domains);
  } catch {
    return new Set();
  }
}

/**
 * Extract the hostname (domain) from a URL string.
 * Returns the raw string lowercased if URL parsing fails.
 * @param {string} url
 * @returns {string}
 */
function extractDomain(url) {
  try {
    // Ensure protocol exists for URL parsing
    const withProto = url.startsWith('http') ? url : `https://${url}`;
    const hostname = new URL(withProto).hostname.toLowerCase();
    // Strip leading www.
    return hostname.replace(/^www\./, '');
  } catch {
    return url.toLowerCase();
  }
}

// ── Public API ───────────────────────────────────────────────

/**
 * Check whether a URL's domain is listed in either exception file.
 * Reads both files fresh from disk on every call.
 * @param {string} url
 * @returns {boolean}
 */
function isDomainExcepted(url) {
  const domain = extractDomain(url);
  const adminSet = loadExceptions(ADMIN_FILE);
  const userSet  = loadExceptions(USER_FILE);
  return adminSet.has(domain) || userSet.has(domain);
}

/**
 * Get the raw contents of both exception files as strings.
 * @returns {{ admin: string, user: string }}
 */
function getExceptionFileContents() {
  let admin = '';
  let user  = '';
  try { admin = fs.readFileSync(ADMIN_FILE, 'utf8').trim(); } catch { admin = '(empty)'; }
  try { user  = fs.readFileSync(USER_FILE,  'utf8').trim(); } catch { user  = '(empty)'; }
  return { admin, user };
}

/**
 * Add a domain to the specified exception file.
 * Prevents duplicate entries (case-insensitive).
 * @param {'admin'|'user'} fileKey
 * @param {string} domain
 * @returns {{ success: boolean, message: string }}
 */
function addDomain(fileKey, domain) {
  const filePath = fileKey === 'admin' ? ADMIN_FILE : USER_FILE;
  const cleaned  = domain.trim().toLowerCase().replace(/^www\./, '');
  const existing = loadExceptions(filePath);

  if (existing.has(cleaned)) {
    return { success: false, message: `${cleaned} is already in the list.` };
  }

  fs.appendFileSync(filePath, `${cleaned}\n`, 'utf8');
  return { success: true, message: `Added ${cleaned} successfully.` };
}

/**
 * Remove a domain from the specified exception file.
 * @param {'admin'|'user'} fileKey
 * @param {string} domain
 * @returns {{ success: boolean, message: string }}
 */
function removeDomain(fileKey, domain) {
  const filePath = fileKey === 'admin' ? ADMIN_FILE : USER_FILE;
  const cleaned  = domain.trim().toLowerCase().replace(/^www\./, '');

  let lines = [];
  try {
    lines = fs.readFileSync(filePath, 'utf8').split('\n');
  } catch {
    return { success: false, message: `Could not read file.` };
  }

  const filtered = lines.filter(
    (line) => line.trim().toLowerCase() !== cleaned && line.trim() !== ''
  );

  if (filtered.length === lines.filter((l) => l.trim()).length) {
    return { success: false, message: `${cleaned} was not found in the list.` };
  }

  fs.writeFileSync(filePath, filtered.join('\n') + '\n', 'utf8');
  return { success: true, message: `Removed ${cleaned} successfully.` };
}

module.exports = {
  isDomainExcepted,
  getExceptionFileContents,
  addDomain,
  removeDomain,
  ADMIN_FILE,
  USER_FILE,
};
