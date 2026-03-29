const CACHE_KEY = 'scoutout_analytics_cache';
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export interface AnalyticsCacheData {
  logs: any[];
  threatsPerDay: any[];
  deviceActivity: any[];
  mostActiveDevices: any[];
  timestamp: number;
}

export const analyticsCache = {
  load(): AnalyticsCacheData | null {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (!cached) return null;

      const data: AnalyticsCacheData = JSON.parse(cached);
      const now = Date.now();

      if (now - data.timestamp > CACHE_TTL) {
        this.clear();
        return null;
      }

      return data;
    } catch (error) {
      console.error('Error loading analytics cache:', error);
      return null;
    }
  },

  save(data: Partial<AnalyticsCacheData>): void {
    try {
      const existing = this.load() || {
        logs: [],
        threatsPerDay: [],
        deviceActivity: [],
        mostActiveDevices: [],
        timestamp: Date.now()
      };

      const updated: AnalyticsCacheData = {
        ...existing,
        ...data,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(updated));
      console.log('[analyticsCache] Saved');
    } catch (error) {
      console.error('Error saving analytics cache:', error);
    }
  },

  clear(): void {
    try {
      localStorage.removeItem(CACHE_KEY);
      console.log('[analyticsCache] Cleared');
    } catch (error) {
      console.error('Error clearing analytics cache:', error);
    }
  }
};

export default analyticsCache;
