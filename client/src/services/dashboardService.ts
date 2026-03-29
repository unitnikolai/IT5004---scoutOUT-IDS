import axios, { AxiosError } from 'axios';

// Dynamically construct API URL based on current frontend location
// If REACT_APP_API_URL is set (Docker), use it. Otherwise detect from window location
const getApiUrl = (): string => {
  // Use environment variable if set (Docker production)
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Otherwise, dynamically detect based on frontend URL
  const protocol = window.location.protocol; // http: or https:
  const hostname = window.location.hostname; // localhost, 192.168.x.x, etc.
  const port = ':5050'; // Backend API port
  const path = '/api';
  
  return `${protocol}//${hostname}${port}${path}`;
};

const API_BASE_URL = getApiUrl();
console.log('[dashboardService] API URL:', API_BASE_URL);

// AbortController for canceling requests
let abortController = new AbortController();

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Helper to safely handle AbortError
const isAbortError = (error: any): boolean => {
  return axios.isCancel(error) || error?.name === 'AbortError' || error?.code === 'ECONNABORTED';
};

export interface DashboardStats {
  totalDevices: number;
  packetsScanned: number;
  threatsBlocked: number;
  parentalBlocks: number;
  networkHealth: number;
}

export interface Alert {
  id: number;
  timestamp: string;
  type: 'threat' | 'device' | 'parental';
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface NewDevice {
  id: number;
  name: string;
  ip: string;
  joinedAt: string;
  type: string;
}

export interface Threat {
  id: number;
  domain: string;
  ip: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  count: number;
}

export interface ThreatActivity {
  time: string;
  threats: number;
}

export interface DashboardResponse<T> {
  stats?: DashboardStats;
  alerts?: Alert[];
  devices?: NewDevice[];
  threats?: Threat[];
  activity?: ThreatActivity[];
  timestamp: string;
}

export const dashboardService = {
  // Cancel all pending requests
  cancelRequests(): void {
    abortController.abort();
    abortController = new AbortController();
  },

  // Get dashboard statistics
  async getStats(): Promise<DashboardResponse<DashboardStats>> {
    try {
      const response = await api.get('/dashboard/stats', {
        signal: abortController.signal
      });
      console.log('[dashboardService.getStats] Response:', response.data);
      return response.data;
    } catch (error) {
      if (!isAbortError(error)) {
        console.error('[dashboardService.getStats] Error:', error);
      }
      throw error;
    }
  },

  // Get recent alerts
  async getAlerts(): Promise<DashboardResponse<Alert[]>> {
    try {
      const response = await api.get('/dashboard/alerts', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error) {
      if (!isAbortError(error)) {
        console.error('[dashboardService.getAlerts] Error:', error);
      }
      throw error;
    }
  },

  // Get new devices
  async getDevices(): Promise<DashboardResponse<NewDevice[]>> {
    try {
      const response = await api.get('/dashboard/devices', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error) {
      if (!isAbortError(error)) {
        console.error('[dashboardService.getDevices] Error:', error);
      }
      throw error;
    }
  },

  // Get top threats
  async getThreats(): Promise<DashboardResponse<Threat[]>> {
    try {
      const response = await api.get('/dashboard/threats', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error) {
      if (!isAbortError(error)) {
        console.error('[dashboardService.getThreats] Error:', error);
      }
      throw error;
    }
  },

  // Get threat activity timeline
  async getActivity(): Promise<DashboardResponse<ThreatActivity[]>> {
    try {
      const response = await api.get('/dashboard/activity', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error) {
      if (!isAbortError(error)) {
        console.error('[dashboardService.getActivity] Error:', error);
      }
      throw error;
    }
  },

  // Get all dashboard data at once
  async getAllData(): Promise<{
    stats: DashboardStats;
    alerts: Alert[];
    devices: NewDevice[];
    threats: Threat[];
    activity: ThreatActivity[];
    timestamp: string;
  }> {
    try {
      const [statsResponse, alertsResponse, devicesResponse, threatsResponse, activityResponse] = await Promise.all([
        dashboardService.getStats(),
        dashboardService.getAlerts(),
        dashboardService.getDevices(),
        dashboardService.getThreats(),
        dashboardService.getActivity()
      ]);

      return {
        stats: statsResponse.stats!,
        alerts: alertsResponse.alerts!,
        devices: devicesResponse.devices!,
        threats: threatsResponse.threats!,
        activity: activityResponse.activity!,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      if (!isAbortError(error)) {
        console.error('[dashboardService.getAllData] Error:', error);
      }
      throw error;
    }
  },
};

export default dashboardService;