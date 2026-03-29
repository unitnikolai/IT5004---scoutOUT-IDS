const CACHE_KEY = 'scoutout_dashboard_cache';
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export interface DashboardCacheData {
  stats: any;
  alerts: any[];
  devices: any[];
  threats: any[];
  activity: any[];
  timestamp: number;
}

export const dashboardCache = {
  load(): DashboardCacheData | null {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (!cached) return null;

      const data: DashboardCacheData = JSON.parse(cached);
      const now = Date.now();

      if (now - data.timestamp > CACHE_TTL) {
        this.clear();
        return null;
      }

      return data;
    } catch (error) {
      console.error('Error loading dashboard cache:', error);
      return null;
    }
  },

  save(data: Partial<DashboardCacheData>): void {
    try {
      const existing = this.load() || {
        stats: {},
        alerts: [],
        devices: [],
        threats: [],
        activity: [],
        timestamp: Date.now()
      };

      const updated: DashboardCacheData = {
        ...existing,
        ...data,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(updated));
      console.log('[dashboardCache] Saved');
    } catch (error) {
      console.error('Error saving dashboard cache:', error);
    }
  },

  clear(): void {
    try {
      localStorage.removeItem(CACHE_KEY);
      console.log('[dashboardCache] Cleared');
    } catch (error) {
      console.error('Error clearing dashboard cache:', error);
    }
  }
};

export default dashboardCache;
