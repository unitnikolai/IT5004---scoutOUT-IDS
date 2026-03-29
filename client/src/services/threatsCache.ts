const CACHE_KEY = 'scoutout_threats_cache';
const MAX_CACHED = 500;
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export interface ThreatsCacheData {
  threats: any[];
  timestamp: number;
}

export const threatsCache = {
  load(): any[] {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (!cached) return [];

      const data: ThreatsCacheData = JSON.parse(cached);
      const now = Date.now();

      if (now - data.timestamp > CACHE_TTL) {
        this.clear();
        return [];
      }

      return data.threats || [];
    } catch (error) {
      console.error('Error loading threats cache:', error);
      return [];
    }
  },

  add(threats: any[]): void {
    try {
      const existing = this.load();
      const existingIds = new Set(existing.map(t => t.id));
      const unique = threats.filter(t => !existingIds.has(t.id));

      if (unique.length === 0) return;

      const combined = [...existing, ...unique];
      const recent = combined.slice(-MAX_CACHED);

      const cacheData: ThreatsCacheData = {
        threats: recent,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[threatsCache] Added ${unique.length} threats, total: ${recent.length}`);
    } catch (error) {
      console.error('Error adding to threats cache:', error);
    }
  },

  replace(threats: any[]): void {
    try {
      const recent = threats.slice(-MAX_CACHED);
      const cacheData: ThreatsCacheData = {
        threats: recent,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[threatsCache] Replaced with ${recent.length} threats`);
    } catch (error) {
      console.error('Error replacing threats cache:', error);
    }
  },

  clear(): void {
    try {
      localStorage.removeItem(CACHE_KEY);
      console.log('[threatsCache] Cleared');
    } catch (error) {
      console.error('Error clearing threats cache:', error);
    }
  }
};

export default threatsCache;
