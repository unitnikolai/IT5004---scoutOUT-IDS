import axios from 'axios';

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

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

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
  // Get dashboard statistics
  async getStats(): Promise<DashboardResponse<DashboardStats>> {
    const response = await api.get('/dashboard/stats');
    console.log('[dashboardService.getStats] Response:', response.data);
    return response.data;
  },

  // Get recent alerts
  async getAlerts(): Promise<DashboardResponse<Alert[]>> {
    const response = await api.get('/dashboard/alerts');
    return response.data;
  },

  // Get new devices
  async getDevices(): Promise<DashboardResponse<NewDevice[]>> {
    const response = await api.get('/dashboard/devices');
    return response.data;
  },

  // Get top threats
  async getThreats(): Promise<DashboardResponse<Threat[]>> {
    const response = await api.get('/dashboard/threats');
    return response.data;
  },

  // Get threat activity timeline
  async getActivity(): Promise<DashboardResponse<ThreatActivity[]>> {
    const response = await api.get('/dashboard/activity');
    return response.data;
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
  },
};

export default dashboardService;