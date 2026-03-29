import { PacketData } from '../types/packet';

const CACHE_KEY = 'scoutout_packets_cache';
const MAX_CACHED_PACKETS = 500; // Keep last 500 packets to avoid bloating localStorage
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

interface CacheData {
  packets: PacketData[];
  timestamp: number;
}

export const packetCache = {
  /**
   * Load cached packets from localStorage
   */
  loadPackets(): PacketData[] {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (!cached) return [];

      const data: CacheData = JSON.parse(cached);
      const now = Date.now();

      // Check if cache is still valid (not expired)
      if (now - data.timestamp > CACHE_TTL) {
        this.clearCache();
        return [];
      }

      return data.packets || [];
    } catch (error) {
      console.error('Error loading packet cache:', error);
      return [];
    }
  },

  /**
   * Save packets to cache, merging with existing packets
   * Keeps only the most recent MAX_CACHED_PACKETS
   */
  savePackets(newPackets: PacketData[]): void {
    try {
      const existing = this.loadPackets();
      
      // Merge: add new packets that aren't already in cache (by ID)
      const existingIds = new Set(existing.map(p => p.id));
      const uniqueNew = newPackets.filter(p => !existingIds.has(p.id));
      
      // Combine and keep only the most recent
      const combined = [...existing, ...uniqueNew];
      const recent = combined.slice(-MAX_CACHED_PACKETS);

      const cacheData: CacheData = {
        packets: recent,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[packetCache] Saved ${recent.length} packets (${uniqueNew.length} new)`);
    } catch (error: any) {
      console.error('Error saving packet cache:', error);
      // If localStorage quota exceeded, clear old data and retry once
      if (error?.name === 'QuotaExceededError' || error?.message?.includes('QuotaExceededError')) {
        console.warn('[packetCache] Storage quota exceeded, clearing old data');
        try {
          localStorage.removeItem(CACHE_KEY);
          // Retry with just the new packets
          const cacheData: CacheData = {
            packets: newPackets.slice(-Math.floor(MAX_CACHED_PACKETS / 2)), // Keep only half
            timestamp: Date.now()
          };
          localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
          console.log('[packetCache] Recovered by reducing cache size');
        } catch (retryError) {
          console.error('[packetCache] Failed to recover storage:', retryError);
        }
      }
    }
  },

  /**
   * Add new packets to cache without losing existing ones
   */
  addPackets(newPackets: PacketData[]): void {
    try {
      if (!newPackets || newPackets.length === 0) {
        console.log('[packetCache] No packets to add');
        return;
      }

      const existing = this.loadPackets();
      
      // Merge avoiding duplicates
      const existingIds = new Set(existing.map(p => p.id));
      const uniqueNew = newPackets.filter(p => !existingIds.has(p.id));
      
      if (uniqueNew.length === 0) {
        console.log('[packetCache] No new unique packets to add');
        return;
      }

      const combined = [...existing, ...uniqueNew];
      const recent = combined.slice(-MAX_CACHED_PACKETS);

      const cacheData: CacheData = {
        packets: recent,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[packetCache] Added ${uniqueNew.length} new packets, total: ${recent.length}, cache size: ${(JSON.stringify(cacheData).length / 1024).toFixed(2)} KB`);
    } catch (error: any) {
      console.error('Error adding packets to cache:', error);
      // If localStorage quota exceeded, clear old data and retry
      if (error?.name === 'QuotaExceededError' || error?.message?.includes('QuotaExceededError')) {
        console.warn('[packetCache] Storage quota exceeded, clearing old data');
        try {
          localStorage.removeItem(CACHE_KEY);
          // Retry with just the new packets
          const cacheData: CacheData = {
            packets: newPackets.slice(-Math.floor(MAX_CACHED_PACKETS / 2)), // Keep only half
            timestamp: Date.now()
          };
          localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
          console.log('[packetCache] Recovered by reducing cache size');
        } catch (retryError) {
          console.error('[packetCache] Failed to recover storage:', retryError);
        }
      }
    }
  },

  /**
   * Replace entire cache with new data
   * Use this when you want to completely reset
   */
  replacePackets(packets: PacketData[]): void {
    try {
      const recent = packets.slice(-MAX_CACHED_PACKETS);
      const cacheData: CacheData = {
        packets: recent,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[packetCache] Replaced with ${recent.length} packets`);
    } catch (error) {
      console.error('Error replacing packet cache:', error);
    }
  },

  /**
   * Clear all cached packets
   */
  clearCache(): void {
    try {
      localStorage.removeItem(CACHE_KEY);
      console.log('[packetCache] Cache cleared');
    } catch (error) {
      console.error('Error clearing cache:', error);
    }
  },

  /**
   * Get cache statistics
   */
  getStats(): { count: number; sizeKB: number; timestamp: number | null } {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (!cached) return { count: 0, sizeKB: 0, timestamp: null };

      const data: CacheData = JSON.parse(cached);
      const sizeKB = Math.round((cached.length / 1024) * 100) / 100;

      return {
        count: data.packets.length,
        sizeKB,
        timestamp: data.timestamp
      };
    } catch (error) {
      console.error('Error getting cache stats:', error);
      return { count: 0, sizeKB: 0, timestamp: null };
    }
  }
};

export default packetCache;
