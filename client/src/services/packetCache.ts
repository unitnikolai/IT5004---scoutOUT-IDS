import { PacketData } from '../types/packet';

const CACHE_KEY = 'scoutout_packets_cache';
const MAX_CACHED_PACKETS = 1000; // Keep last 1000 packets to avoid bloating localStorage
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
    } catch (error) {
      console.error('Error saving packet cache:', error);
    }
  },

  /**
   * Add new packets to cache without losing existing ones
   */
  addPackets(newPackets: PacketData[]): void {
    try {
      const existing = this.loadPackets();
      
      if (existing.length === 0) {
        this.savePackets(newPackets);
        return;
      }

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
      console.log(`[packetCache] Added ${uniqueNew.length} new packets, total: ${recent.length}`);
    } catch (error) {
      console.error('Error adding packets to cache:', error);
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
