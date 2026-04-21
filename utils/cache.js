// ============================================================
//  utils/cache.js  —  1-hour TTL scan result cache
// ============================================================

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

class ScanCache {
  constructor() {
    /** @type {Map<string, { result: object, expiresAt: number }>} */
    this._store = new Map();
  }

  /**
   * Retrieve a cached scan result for the given URL.
   * Returns null if not found or expired.
   * @param {string} url
   * @returns {object|null}
   */
  get(url) {
    const entry = this._store.get(url);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this._store.delete(url);
      return null;
    }
    return entry.result;
  }

  /**
   * Store a scan result for the given URL with a 1-hour TTL.
   * @param {string} url
   * @param {object} result
   */
  set(url, result) {
    this._store.set(url, {
      result,
      expiresAt: Date.now() + CACHE_TTL_MS,
    });
  }

  /**
   * Remove a cached entry manually (e.g., after exception list changes).
   * @param {string} url
   */
  delete(url) {
    this._store.delete(url);
  }

  /** Clear the entire cache. */
  clear() {
    this._store.clear();
  }
}

// Export a single shared instance
module.exports = new ScanCache();
