const CACHE_KEY = 'scoutout_devices_cache';
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export interface DevicesCacheData {
  devices: any[];
  timestamp: number;
}

export const devicesCache = {
  load(): any[] {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (!cached) return [];

      const data: DevicesCacheData = JSON.parse(cached);
      const now = Date.now();

      if (now - data.timestamp > CACHE_TTL) {
        this.clear();
        return [];
      }

      return data.devices || [];
    } catch (error) {
      console.error('Error loading devices cache:', error);
      return [];
    }
  },

  add(devices: any[]): void {
    try {
      const existing = this.load();
      const existingIds = new Set(existing.map(d => d.id));
      const unique = devices.filter(d => !existingIds.has(d.id));

      if (unique.length === 0) {
        console.log('[devicesCache] No new unique devices');
        return;
      }

      const combined = [...existing, ...unique];

      const cacheData: DevicesCacheData = {
        devices: combined,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[devicesCache] Added ${unique.length} devices, total: ${combined.length}`);
    } catch (error) {
      console.error('Error adding to devices cache:', error);
    }
  },

  replace(devices: any[]): void {
    try {
      const cacheData: DevicesCacheData = {
        devices: devices,
        timestamp: Date.now()
      };

      localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData));
      console.log(`[devicesCache] Replaced with ${devices.length} devices`);
    } catch (error) {
      console.error('Error replacing devices cache:', error);
    }
  },

  clear(): void {
    try {
      localStorage.removeItem(CACHE_KEY);
      console.log('[devicesCache] Cleared');
    } catch (error) {
      console.error('Error clearing devices cache:', error);
    }
  }
};

export default devicesCache;
