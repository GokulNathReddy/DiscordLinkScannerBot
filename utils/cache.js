// ============================================================
//  utils/cache.js  —  Scan result cache (URL + file hashes)
//
//  Railway free tier has ~512 MB RAM shared with the Node process.
//  Both caches are capped by entry count so they can never grow
//  unbounded. Each URL entry is ~1-2 KB of JSON; 500 entries ~= 1 MB.
//  Each hash entry is ~2 KB; 300 entries ~= 0.6 MB. Total ceiling
//  is well under 5 MB — negligible against the 512 MB limit.
//
//  CPU cost is zero between scans: Map lookups are O(1) and the
//  periodic cleanup runs only every 10 minutes.
// ============================================================

// ── URL scan result cache ─────────────────────────────────────
const URL_CACHE_TTL_MS = 60 * 60 * 1000;   // 1 hour
const URL_CACHE_MAX    = 500;               // max entries

// ── File hash result cache ────────────────────────────────────
const HASH_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const HASH_CACHE_MAX    = 300;                  // max entries

// ── Generic bounded TTL store ─────────────────────────────────
class BoundedCache {
  constructor(ttlMs, maxSize) {
    this._ttl   = ttlMs;
    this._max   = maxSize;
    this._store = new Map(); // insertion-ordered → oldest = first key
  }

  get(key) {
    const entry = this._store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this._store.delete(key); return null; }
    return entry.value;
  }

  set(key, value) {
    // Evict the single oldest entry when at capacity
    if (!this._store.has(key) && this._store.size >= this._max) {
      const oldestKey = this._store.keys().next().value;
      this._store.delete(oldestKey);
    }
    this._store.set(key, { value, expiresAt: Date.now() + this._ttl });
  }

  delete(key) { this._store.delete(key); }
  clear()     { this._store.clear(); }
  get size()  { return this._store.size; }

  /** Remove all expired entries (called by periodic timer). */
  purgeExpired() {
    const now = Date.now();
    for (const [k, v] of this._store) {
      if (now > v.expiresAt) this._store.delete(k);
    }
  }
}

// ── Singleton instances ───────────────────────────────────────
const urlCache  = new BoundedCache(URL_CACHE_TTL_MS,  URL_CACHE_MAX);
const hashCache = new BoundedCache(HASH_CACHE_TTL_MS, HASH_CACHE_MAX);

// ── Periodic cleanup every 10 min ────────────────────────────
// Prevents stale entries piling up. .unref() means this timer
// will not keep the process alive by itself.
setInterval(() => {
  urlCache.purgeExpired();
  hashCache.purgeExpired();
}, 10 * 60 * 1000).unref();

// ── Public exports ────────────────────────────────────────────
// urlCache is the default export (backwards-compatible with scanner.js)
module.exports        = urlCache;
// hashCache is attached so fileScanner.js can import it from the same module
module.exports.hashCache = hashCache;
