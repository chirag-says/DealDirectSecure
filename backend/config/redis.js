/**
 * Redis Configuration — DealDirect Loyalty Wallet
 * 
 * Provides a Redis client for caching wallet balances, tier data,
 * and rate limiting. Falls back gracefully if Redis is unavailable.
 */

// ============================================
// REDIS CLIENT PLACEHOLDER
// ============================================
// 
// Redis is OPTIONAL for Phase 1. The loyalty engine works
// without Redis — it just won't have caching.
// 
// To enable Redis, install ioredis and uncomment the real client below:
//   npm install ioredis
//
// Then set REDIS_URL in your .env:
//   REDIS_URL=redis://localhost:6379
//   or
//   REDIS_URL=redis://default:password@redis-cloud-host:port

// import Redis from 'ioredis';

class MemoryCache {
    constructor() {
        this.store = new Map();
        this.timers = new Map();
        console.log('⚠️ Using in-memory cache (Redis not configured). Set REDIS_URL for production.');
    }

    async get(key) {
        const item = this.store.get(key);
        if (!item) return null;
        if (item.expiresAt && Date.now() > item.expiresAt) {
            this.store.delete(key);
            return null;
        }
        return item.value;
    }

    async set(key, value, ...args) {
        let ttlSeconds = null;
        // Support: set(key, value, 'EX', seconds) pattern
        if (args[0] === 'EX' && args[1]) {
            ttlSeconds = parseInt(args[1]);
        }

        const item = {
            value,
            expiresAt: ttlSeconds ? Date.now() + (ttlSeconds * 1000) : null,
        };

        this.store.set(key, item);

        // Auto-cleanup expired keys
        if (ttlSeconds) {
            if (this.timers.has(key)) clearTimeout(this.timers.get(key));
            this.timers.set(key, setTimeout(() => {
                this.store.delete(key);
                this.timers.delete(key);
            }, ttlSeconds * 1000));
        }

        return 'OK';
    }

    async del(key) {
        this.store.delete(key);
        if (this.timers.has(key)) {
            clearTimeout(this.timers.get(key));
            this.timers.delete(key);
        }
        return 1;
    }

    async incr(key) {
        const current = await this.get(key);
        const newVal = (parseInt(current) || 0) + 1;
        // Preserve existing TTL
        const item = this.store.get(key);
        if (item) {
            item.value = newVal.toString();
        } else {
            await this.set(key, newVal.toString());
        }
        return newVal;
    }

    async expire(key, seconds) {
        const item = this.store.get(key);
        if (item) {
            item.expiresAt = Date.now() + (seconds * 1000);
            if (this.timers.has(key)) clearTimeout(this.timers.get(key));
            this.timers.set(key, setTimeout(() => {
                this.store.delete(key);
                this.timers.delete(key);
            }, seconds * 1000));
        }
        return 1;
    }

    async flushPattern(pattern) {
        // Simple pattern matching for cache invalidation
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        for (const key of this.store.keys()) {
            if (regex.test(key)) {
                this.store.delete(key);
                if (this.timers.has(key)) {
                    clearTimeout(this.timers.get(key));
                    this.timers.delete(key);
                }
            }
        }
    }

    get status() {
        return 'ready';
    }
}

// ============================================
// CREATE CLIENT
// ============================================

let redisClient;

if (process.env.REDIS_URL) {
    try {
        // Uncomment when ioredis is installed:
        // const Redis = (await import('ioredis')).default;
        // redisClient = new Redis(process.env.REDIS_URL, {
        //   maxRetriesPerRequest: 3,
        //   retryStrategy: (times) => Math.min(times * 50, 2000),
        //   lazyConnect: true,
        // });
        // await redisClient.connect();
        // console.log('✅ Redis connected:', process.env.REDIS_URL.replace(/\/\/.*@/, '//***@'));

        // For now, use memory cache even if REDIS_URL is set
        redisClient = new MemoryCache();
    } catch (err) {
        console.warn('⚠️ Redis connection failed, falling back to memory cache:', err.message);
        redisClient = new MemoryCache();
    }
} else {
    redisClient = new MemoryCache();
}

// ============================================
// CACHE HELPERS
// ============================================

/**
 * Get cached value, or compute and cache it
 * @param {string} key - Cache key
 * @param {number} ttlSeconds - Time to live in seconds
 * @param {Function} computeFn - Async function to compute value if not cached
 */
export const cacheOrCompute = async (key, ttlSeconds, computeFn) => {
    try {
        const cached = await redisClient.get(key);
        if (cached) {
            return JSON.parse(cached);
        }
    } catch (err) {
        // Cache read failed, proceed to compute
    }

    const result = await computeFn();

    try {
        await redisClient.set(key, JSON.stringify(result), 'EX', ttlSeconds);
    } catch (err) {
        // Cache write failed, not critical
    }

    return result;
};

/**
 * Invalidate cache by key or pattern
 */
export const invalidateCache = async (keyOrPattern) => {
    try {
        if (keyOrPattern.includes('*')) {
            await redisClient.flushPattern(keyOrPattern);
        } else {
            await redisClient.del(keyOrPattern);
        }
    } catch (err) {
        // Cache invalidation failed, not critical
    }
};

export default redisClient;
